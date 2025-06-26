require "big"
require "base64"
require "../base/asymmetric_algorithm"
require "../hashes/sha1"

module Crypto::Asymmetric
  # RSA key structure
  struct RSAKey
    property n : BigInt    # modulus
    property e : BigInt    # public exponent
    property d : BigInt?   # private exponent (nil for public key only)
    property p : BigInt?   # first prime factor
    property q : BigInt?   # second prime factor
    property dp : BigInt?  # d mod (p-1)
    property dq : BigInt?  # d mod (q-1)
    property qinv : BigInt? # q^-1 mod p

    def initialize(@n : BigInt, @e : BigInt, @d : BigInt? = nil, @p : BigInt? = nil, @q : BigInt? = nil, @dp : BigInt? = nil, @dq : BigInt? = nil, @qinv : BigInt? = nil)
    end

    # Check if this is a private key
    def private?
      !@d.nil?
    end

    # Get public key from this key
    def public_key
      RSAKey.new(@n, @e)
    end

    # Get key size in bits
    def key_size
      @n.bit_length
    end

    # Calculate RSA fingerprint for MTProto (SHA-1 of public key DER)
    def fingerprint : Bytes
      der_bytes = to_der_public_key
      sha1 = Crypto::Hashes::Sha1.new
      hash = sha1.hash_bytes(der_bytes)
      # Return last 8 bytes as fingerprint (MTProto convention)
      hash[-8..-1]
    end

    # Export public key as DER format
    def to_der_public_key : Bytes
      # ASN.1 DER encoding of RSA public key
      # RSAPublicKey ::= SEQUENCE {
      #     modulus           INTEGER,  -- n
      #     publicExponent    INTEGER   -- e
      # }

      n_bytes = bigint_to_der_integer(@n)
      e_bytes = bigint_to_der_integer(@e)

      # Create the SEQUENCE
      sequence_content = n_bytes + e_bytes
      sequence_bytes = der_encode_sequence(sequence_content)

      # Wrap in AlgorithmIdentifier and BIT STRING for SubjectPublicKeyInfo
      # But for MTProto, we typically just need the RSAPublicKey part
      sequence_bytes
    end

    # Export public key as PEM format
    def to_pem_public_key : String
      der_bytes = to_der_public_key

      # Create full SubjectPublicKeyInfo structure
      # algorithmIdentifier
      rsa_oid = Bytes[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

      # BIT STRING containing the RSA public key
      bit_string = der_encode_bit_string(der_bytes)

      # Complete SubjectPublicKeyInfo
      spki_content = rsa_oid + bit_string
      spki_der = der_encode_sequence(spki_content)

      base64_content = Base64.strict_encode(spki_der)

      # Format as PEM
      lines = [] of String
      lines << "-----BEGIN PUBLIC KEY-----"
      base64_content.scan(/.{1,64}/).each { |match| lines << match[0] }
      lines << "-----END PUBLIC KEY-----"
      lines.join("\n")
    end

    private def bigint_to_der_integer(value : BigInt) : Bytes
      # Convert BigInt to bytes
      hex_str = value.to_s(16)
      hex_str = "0" + hex_str if hex_str.size.odd?

      bytes = hex_str.scan(/../).map(&.[0].to_u8(16))

      # Add leading zero if MSB is set (to ensure positive integer)
      if bytes.first >= 0x80
        bytes.unshift(0_u8)
      end

      # Create DER INTEGER
      content = Bytes.new(bytes.size)
      bytes.each_with_index { |byte, i| content[i] = byte }

      der_encode_integer(content)
    end

    private def der_encode_integer(content : Bytes) : Bytes
      length_bytes = encode_der_length(content.size)
      result = Bytes.new(1 + length_bytes.size + content.size)
      result[0] = 0x02_u8  # INTEGER tag
      length_bytes.each_with_index { |byte, i| result[1 + i] = byte }
      content.each_with_index { |byte, i| result[1 + length_bytes.size + i] = byte }
      result
    end

    private def der_encode_sequence(content : Bytes) : Bytes
      length_bytes = encode_der_length(content.size)
      result = Bytes.new(1 + length_bytes.size + content.size)
      result[0] = 0x30_u8  # SEQUENCE tag
      length_bytes.each_with_index { |byte, i| result[1 + i] = byte }
      content.each_with_index { |byte, i| result[1 + length_bytes.size + i] = byte }
      result
    end

    private def der_encode_bit_string(content : Bytes) : Bytes
      # BIT STRING with no unused bits
      length_bytes = encode_der_length(content.size + 1)
      result = Bytes.new(1 + length_bytes.size + 1 + content.size)
      result[0] = 0x03_u8  # BIT STRING tag
      length_bytes.each_with_index { |byte, i| result[1 + i] = byte }
      result[1 + length_bytes.size] = 0x00_u8  # no unused bits
      content.each_with_index { |byte, i| result[1 + length_bytes.size + 1 + i] = byte }
      result
    end

    private def encode_der_length(length : Int32) : Bytes
      if length < 0x80
        Bytes[length.to_u8]
      else
        # Long form
        length_bytes = [] of UInt8
        temp = length
        while temp > 0
          length_bytes.unshift((temp & 0xff).to_u8)
          temp >>= 8
        end

        result = Bytes.new(1 + length_bytes.size)
        result[0] = (0x80 | length_bytes.size).to_u8
        length_bytes.each_with_index { |byte, i| result[1 + i] = byte }
        result
      end
    end
  end

  # RSA implementation with MTProto support
  class RSA < AsymmetricEncryption
    @key : RSAKey

    def initialize(@key : RSAKey)
    end

    # Create RSA instance from key components
    def self.new(n : BigInt, e : BigInt, d : BigInt? = nil, p : BigInt? = nil, q : BigInt? = nil)
      key = RSAKey.new(n, e, d, p, q)
      new(key)
    end

    # Parse RSA key from PEM format
    def self.from_pem(pem_string : String) : RSA
      # Remove PEM headers and decode base64
      clean_pem = pem_string.gsub(/-----[^-]+-----/, "").gsub(/\s/, "")
      der_bytes = Base64.decode(clean_pem)

      from_der(der_bytes)
    end

    # Parse RSA key from DER format
    def self.from_der(der_bytes : Bytes) : RSA
      # Simple DER parser for RSA keys
      # This is a basic implementation - production code should use a proper ASN.1 parser

      offset = 0

      # Skip SEQUENCE tag and length
      raise "Invalid DER: expected SEQUENCE" unless der_bytes[offset] == 0x30
      offset += 1
      _, offset = parse_der_length(der_bytes, offset)

      # For SubjectPublicKeyInfo, skip the AlgorithmIdentifier
      if der_bytes[offset] == 0x30  # Another SEQUENCE (AlgorithmIdentifier)
        offset += 1
        alg_length, offset = parse_der_length(der_bytes, offset)
        offset += alg_length  # Skip AlgorithmIdentifier

        # Next should be BIT STRING containing the actual key
        raise "Invalid DER: expected BIT STRING" unless der_bytes[offset] == 0x03
        offset += 1
        _, offset = parse_der_length(der_bytes, offset)
        offset += 1  # Skip unused bits byte

        # Now we should have the RSA public key SEQUENCE
        raise "Invalid DER: expected SEQUENCE" unless der_bytes[offset] == 0x30
      end

      # Parse RSA public key SEQUENCE
      offset += 1
      _, offset = parse_der_length(der_bytes, offset)

      # Parse modulus (n)
      raise "Invalid DER: expected INTEGER" unless der_bytes[offset] == 0x02
      n, offset = parse_der_integer(der_bytes, offset)

      # Parse public exponent (e)
      raise "Invalid DER: expected INTEGER" unless der_bytes[offset] == 0x02
      e, _ = parse_der_integer(der_bytes, offset)

      key = RSAKey.new(n, e)
      new(key)
    end


    # Encrypt with RSA using PKCS#1 v1.5 padding (required for MTProto)
    def encrypt(data : Bytes) : Bytes
      raise "Cannot encrypt: no public key" if @key.n.nil? || @key.e.nil?
      raise "Data too large for RSA key" if data.size >= (@key.key_size - 88) // 8

      # Apply PKCS#1 v1.5 padding
      padded = pkcs1_v15_pad(data, @key.key_size // 8, pad_type: 2)

      # Convert to BigInt
      message = bytes_to_bigint(padded)

      # RSA encryption: c = m^e mod n
      ciphertext = message ** @key.e % @key.n

      # Convert back to bytes
      bigint_to_bytes(ciphertext, @key.key_size // 8)
    end

    # Decrypt with RSA using PKCS#1 v1.5 padding
    def decrypt(data : Bytes) : Bytes
      raise "Cannot decrypt: no private key" unless @key.private?
      raise "Invalid ciphertext size" if data.size != @key.key_size // 8

      # Convert to BigInt
      ciphertext = bytes_to_bigint(data)

      # RSA decryption: m = c^d mod n
      if @key.p && @key.q && @key.dp && @key.dq && @key.qinv
        # Use Chinese Remainder Theorem for faster decryption
        message = rsa_crt_decrypt(ciphertext)
      else
        message = ciphertext ** @key.d.not_nil! % @key.n
      end

      # Convert back to bytes
      padded = bigint_to_bytes(message, @key.key_size // 8)

      # Remove PKCS#1 v1.5 padding
      pkcs1_v15_unpad(padded)
    end

    # Returns the public key as bytes (DER format)
    def public_key : Bytes
      @key.to_der_public_key
    end

    # Returns the key size in bits
    def key_size : Int32
      @key.key_size
    end

    # Get RSA fingerprint for MTProto
    def fingerprint : Bytes
      @key.fingerprint
    end

    # Get RSA fingerprint as integer (for MTProto)
    def fingerprint_int : Int64
      fp = fingerprint
      result = 0_i64
      fp.each_with_index do |byte, i|
        result |= byte.to_i64 << (i * 8)
      end
      result
    end

    # Get RSA fingerprint as hex string
    def fingerprint_hex : String
      fingerprint.hexstring
    end

    private def rsa_crt_decrypt(ciphertext : BigInt) : BigInt
      p = @key.p.not_nil!
      q = @key.q.not_nil!
      dp = @key.dp.not_nil!
      dq = @key.dq.not_nil!
      qinv = @key.qinv.not_nil!

      # Chinese Remainder Theorem
      m1 = ciphertext ** dp % p
      m2 = ciphertext ** dq % q

      h = ((m1 - m2) * qinv) % p
      message = m2 + (h * q)

      message
    end

    private def pkcs1_v15_pad(data : Bytes, key_length : Int32, pad_type : Int32) : Bytes
      # PKCS#1 v1.5 padding
      # 00 || BT || PS || 00 || D

      ps_length = key_length - data.size - 3
      raise "Data too large for key" if ps_length < 8

      result = Bytes.new(key_length)
      result[0] = 0x00_u8
      result[1] = pad_type.to_u8

      if pad_type == 1
        # Type 1: PS is all 0xFF (for signatures)
        (2...2 + ps_length).each { |i| result[i] = 0xFF_u8 }
      else
        # Type 2: PS is random non-zero bytes (for encryption)
        (2...2 + ps_length).each do |i|
          loop do
            byte = Random.rand(256).to_u8
            if byte != 0
              result[i] = byte
              break
            end
          end
        end
      end

      result[2 + ps_length] = 0x00_u8
      data.each_with_index { |byte, i| result[3 + ps_length + i] = byte }

      result
    end

    private def pkcs1_v15_unpad(padded : Bytes) : Bytes
      raise "Invalid padding" if padded.size < 11
      raise "Invalid padding" if padded[0] != 0x00

      pad_type = padded[1]
      raise "Invalid padding type" unless pad_type == 1 || pad_type == 2

      # Find the 0x00 separator
      separator_index = -1
      (2...padded.size).each do |i|
        if padded[i] == 0x00
          separator_index = i
          break
        end
      end

      raise "Invalid padding: no separator found" if separator_index == -1
      raise "Invalid padding: too short" if separator_index < 10

      # Return the data after the separator
      data_start = separator_index + 1
      result = Bytes.new(padded.size - data_start)
      (data_start...padded.size).each_with_index do |i, j|
        result[j] = padded[i]
      end

      result
    end

    private def bytes_to_bigint(bytes : Bytes) : BigInt
      result = BigInt.new(0)
      bytes.each do |byte|
        result = (result << 8) | byte.to_big_i
      end
      result
    end

    private def bigint_to_bytes(value : BigInt, length : Int32) : Bytes
      result = Bytes.new(length)
      temp = value

      (length - 1).downto(0) do |i|
        result[i] = (temp & 0xff).to_u8
        temp >>= 8
      end

      result
    end

    # Modular exponentiation: base^exp mod modulus
    # Uses binary exponentiation to avoid overflow
    private def mod_pow(base : BigInt, exp : BigInt, modulus : BigInt) : BigInt
      return BigInt.new(1) if exp == 0
      return BigInt.new(0) if modulus == 1

      result = BigInt.new(1)
      base = base % modulus
      exp_copy = exp

      while exp_copy > 0
        if exp_copy.odd?
          result = (result * base) % modulus
        end
        exp_copy >>= 1
        base = (base * base) % modulus
      end

      result
    end

    private def self.parse_der_length(bytes : Bytes, offset : Int32) : {Int32, Int32}
      first_byte = bytes[offset]
      offset += 1

      if first_byte & 0x80 == 0
        # Short form
        {first_byte.to_i32, offset}
      else
        # Long form
        length_bytes = first_byte & 0x7f
        raise "Invalid DER length" if length_bytes == 0 || length_bytes > 4

        length = 0
        length_bytes.times do
          length = (length << 8) | bytes[offset]
          offset += 1
        end

        {length, offset}
      end
    end

    private def self.parse_der_integer(bytes : Bytes, offset : Int32) : {BigInt, Int32}
      raise "Invalid DER: expected INTEGER" unless bytes[offset] == 0x02
      offset += 1

      length, offset = parse_der_length(bytes, offset)

      result = BigInt.new(0)
      length.times do
        result = (result << 8) | bytes[offset].to_big_i
        offset += 1
      end

      {result, offset}
    end
  end
end
