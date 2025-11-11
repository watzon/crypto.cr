require "big"
require "../base/asymmetric_algorithm"
require "../hashes/sha256"
require "../hashes/sha3"

module Crypto
  module Asymmetric
    # Elliptic curve point representation
    struct ECPoint
      property x : BigInt
      property y : BigInt
      property infinity : Bool

      def initialize(@x : BigInt, @y : BigInt, @infinity : Bool = false)
      end

      # Create point at infinity
      def self.infinity
        ECPoint.new(BigInt.new(0), BigInt.new(0), true)
      end

      # Check if point is at infinity
      def infinity?
        @infinity
      end

      # Check if two points are equal
      def ==(other : ECPoint)
        if @infinity && other.infinity?
          return true
        elsif @infinity || other.infinity?
          return false
        else
          return @x == other.x && @y == other.y
        end
      end

      # Add two points on the curve
      def add(other : ECPoint, curve : EllipticCurve) : ECPoint
        if @infinity
          return other
        elsif other.infinity?
          return self
        elsif @x == other.x
          if @y == other.y
            # Point doubling
            double(curve)
          else
            # P + (-P) = O (point at infinity)
            ECPoint.infinity
          end
        else
          # Point addition
          s = ((other.y - @y) * Crypto.mod_inverse(other.x - @x, curve.p)) % curve.p
          x3 = (s * s - @x - other.x) % curve.p
          y3 = (s * (@x - x3) - @y) % curve.p
          ECPoint.new(x3, y3)
        end
      end

      # Double a point
      def double(curve : EllipticCurve) : ECPoint
        if @infinity
          return self
        end

        # s = (3x² + a) / (2y) mod p
        s = ((3 * @x * @x + curve.a) * Crypto.mod_inverse(2 * @y, curve.p)) % curve.p
        x3 = (s * s - 2 * @x) % curve.p
        y3 = (s * (@x - x3) - @y) % curve.p
        ECPoint.new(x3, y3)
      end

      # Scalar multiplication: k * P
      def multiply(k : BigInt, curve : EllipticCurve) : ECPoint
        result = ECPoint.infinity
        addend = self
        k_copy = k.abs

        while k_copy > 0
          if k_copy.odd?
            result = result.add(addend, curve)
          end
          addend = addend.double(curve)
          k_copy >>= 1
        end

        result
      end

      # Check if point is on the curve
      def on_curve?(curve : EllipticCurve) : Bool
        return true if @infinity
        # y² ≡ x³ + ax + b (mod p)
        (@y * @y) % curve.p == ((@x * @x * @x + curve.a * @x + curve.b) % curve.p)
      end

      # Convert to uncompressed bytes (0x04 || x || y)
      def to_bytes_uncompressed(field_size : Int32) : Bytes
        return Bytes[0] if @infinity

        x_bytes = bigint_to_bytes(@x, field_size)
        y_bytes = bigint_to_bytes(@y, field_size)

        result = Bytes.new(1 + field_size * 2)
        result[0] = 0x04_u8  # Uncompressed
        x_bytes.each_with_index { |byte, i| result[1 + i] = byte }
        y_bytes.each_with_index { |byte, i| result[1 + field_size + i] = byte }
        result
      end

      # Convert to compressed bytes (0x02/0x03 || x)
      def to_bytes_compressed(field_size : Int32) : Bytes
        return Bytes[0] if @infinity

        x_bytes = bigint_to_bytes(@x, field_size)

        result = Bytes.new(1 + field_size)
        result[0] = (@y.even?) ? 0x02_u8 : 0x03_u8  # Compressed
        x_bytes.each_with_index { |byte, i| result[1 + i] = byte }
        result
      end

      # Parse from bytes
      def self.from_bytes(bytes : Bytes, curve : EllipticCurve) : ECPoint
        return ECPoint.infinity if bytes.size == 0

        if bytes.size == 1 && bytes[0] == 0x00
          return ECPoint.infinity  # Special case for point at infinity
        end

        field_size = (curve.p.bit_length + 7) // 8

        case bytes[0]
        when 0x04  # Uncompressed
          if bytes.size != 1 + field_size * 2
            raise "Invalid uncompressed point format"
          end
          x = bytes_to_bigint(bytes[1, field_size])
          y = bytes_to_bigint(bytes[1 + field_size, field_size])
          ECPoint.new(x, y)
        when 0x02, 0x03  # Compressed
          if bytes.size != 1 + field_size
            raise "Invalid compressed point format"
          end
          x = bytes_to_bigint(bytes[1, field_size])

          # y² = x³ + ax + b
          y_squared = (x * x * x + curve.a * x + curve.b) % curve.p
          y = Crypto.mod_sqrt(y_squared, curve.p)

          if y.nil?
            raise "Invalid compressed point - no square root"
          end

          # Choose the correct y based on the prefix
          if (bytes[0] == 0x02 && y.odd?) || (bytes[0] == 0x03 && y.even?)
            y = curve.p - y
          end

          ECPoint.new(x, y)
        else
          raise "Unsupported point format"
        end
      end

      private def self.bytes_to_bigint(bytes : Bytes) : BigInt
        result = BigInt.new(0)
        bytes.each { |byte| result = (result << 8) | byte.to_big_i }
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

      # Modular inverse using extended Euclidean algorithm
      private def mod_inverse(a : BigInt, m : BigInt) : BigInt
        return 0 if a == 0
        lm, hm = 1, 0
        low, high = a % m, m

        while low > 1
          r = high // low
          nm, new = hm - lm * r, high - low * r
          lm, low, hm, high = nm, new, lm, low
        end

        lm % m
      end

      # Modular square root (Tonelli-Shanks algorithm)
      def self.mod_sqrt(a : BigInt, p : BigInt) : BigInt?
        return 0 if a == 0
        return nil unless a == pow_mod(a, (p - 1) // 2, p) == 1

        # Find q and s such that p-1 = q*2^s with q odd
        q = p - 1
        s = 0
        while q.even?
          q >>= 1
          s += 1
        end

        # Find a non-square z
        z = 2
        while pow_mod(z, (p - 1) // 2, p) == 1
          z += 1
        end

        c = pow_mod(z, q, p)
        x = pow_mod(a, (q + 1) // 2, p)
        t = pow_mod(a, q, p)
        m = s

        while t != 1
          # Find the smallest i (0 < i < m) such that t^(2^i) = 1
          i = 1
          temp = (t * t) % p
          while i < m && temp != 1
            temp = (temp * temp) % p
            i += 1
          end

          return nil if i == m

          b = pow_mod(c, BigInt.new(2) << (m - i - 1), p)
          x = (x * b) % p
          t = (t * b * b) % p
          c = (b * b) % p
          m = i
        end

        x
      end

      # Modular exponentiation
      def self.pow_mod(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
        result = BigInt.new(1)
        base_copy = base % mod
        exp_copy = exp

        while exp_copy > 0
          result = (result * base_copy) % mod if exp_copy.odd?
          base_copy = (base_copy * base_copy) % mod
          exp_copy >>= 1
        end

        result
      end
    end

    # Base elliptic curve class
    abstract class EllipticCurve
      property p : BigInt      # Prime field modulus
      property a : BigInt      # Curve parameter a
      property b : BigInt      # Curve parameter b
      property g : ECPoint     # Base point (generator)
      property n : BigInt      # Order of the base point
      property h : BigInt      # Cofactor

      abstract def name : String
      abstract def key_size : Int32

      def initialize(@p : BigInt, @a : BigInt, @b : BigInt, @g : ECPoint, @n : BigInt, @h : BigInt)
      end

      # Check if point is on this curve
      def point_on_curve?(point : ECPoint) : Bool
        point.on_curve?(self)
      end

      # Scalar multiplication
      def scalar_multiply(k : BigInt, point : ECPoint) : ECPoint
        point.multiply(k, self)
      end

      # Generate a random private key
      def generate_private_key : BigInt
        # Generate secure random bytes and convert to BigInt
        bytes = Bytes.new(key_size // 8)
        Random::Secure.random_bytes(bytes)

        k = BigInt.new(0)
        bytes.each do |byte|
          k = (k << 8) | byte.to_u64
        end

        # Ensure it's in the valid range [1, n-1]
        k = k % (@n - 1) + 1
        k
      end

      # Derive public key from private key
      def derive_public_key(private_key : BigInt) : ECPoint
        scalar_multiply(private_key, @g)
      end
    end

    # ECDSA signature structure
    struct ECDSASignature
      property r : BigInt
      property s : BigInt

      def initialize(@r : BigInt, @s : BigInt)
      end

      # Convert to DER format
      def to_der : Bytes
        r_der = integer_to_der(@r)
        s_der = integer_to_der(@s)

        sequence_content = r_der + s_der
        der_encode_sequence(sequence_content)
      end

      # Parse from DER format
      def self.from_der(bytes : Bytes) : ECDSASignature
        offset = 0

        # Skip SEQUENCE tag and length
        raise "Invalid DER: expected SEQUENCE" unless bytes[offset] == 0x30
        offset += 1
        _, offset = parse_der_length(bytes, offset)

        # Parse r
        raise "Invalid DER: expected INTEGER" unless bytes[offset] == 0x02
        r, offset = parse_der_integer(bytes, offset)

        # Parse s
        raise "Invalid DER: expected INTEGER" unless bytes[offset] == 0x02
        s, _ = parse_der_integer(bytes, offset)

        new(r, s)
      end

      private def integer_to_der(value : BigInt) : Bytes
        hex_str = value.to_s(16)
        hex_str = "0" + hex_str if hex_str.size.odd?

        bytes = hex_str.scan(/../).map(&.[0].to_u8(16))

        # Add leading zero if MSB is set
        if bytes.first >= 0x80
          bytes.unshift(0_u8)
        end

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

  # Helper functions for elliptic curve operations
  def self.mod_inverse(a : BigInt, m : BigInt) : BigInt
    return BigInt.new(0) if a == 0
    lm, hm = 1, 0
    low, high = a % m, m

    max_iterations = 1000
    iterations = 0
    while low > 1 && iterations < max_iterations
      if low == 0  # Prevent division by zero
        return BigInt.new(0)
      end
      r = high // low
      nm, new = hm - lm * r, high - low * r
      lm, low, hm, high = nm, new, lm, low
      iterations += 1
    end

    return BigInt.new(0) if iterations >= max_iterations  # Should never happen for valid inputs
    BigInt.new(lm % m)
  end

  def self.mod_sqrt(a : BigInt, p : BigInt) : BigInt?
    return BigInt.new(0) if a == 0
    return nil unless Crypto.pow_mod(a, (p - 1) // 2, p) == 1

    # Find q and s such that p-1 = q*2^s with q odd
    q = p - 1
    s = 0
    while q.even?
      q >>= 1
      s += 1
    end

    # Find a non-square z with safeguard
    z = 2
    max_attempts = 100
    attempts = 0
    while attempts < max_attempts && Crypto.pow_mod(BigInt.new(z), BigInt.new((p - 1) // 2), p) == 1
      z += 1
      attempts += 1
    end
    return nil if attempts >= max_attempts  # Should never happen for prime p

    c = Crypto.pow_mod(BigInt.new(z), q, p)
    x = Crypto.pow_mod(a, BigInt.new((q + 1) // 2), p)
    t = Crypto.pow_mod(a, q, p)
    m = s

    max_iterations = 100
    iterations = 0
    while t != 1 && iterations < max_iterations
      # Find the smallest i (0 < i < m) such that t^(2^i) = 1
      i = 1
      temp = (t * t) % p
      while i < m && temp != 1
        temp = (temp * temp) % p
        i += 1
      end

      return nil if i == m || iterations >= max_iterations

      b = Crypto.pow_mod(c, BigInt.new(2) << (m - i - 1), p)
      x = (x * b) % p
      t = (t * b * b) % p
      c = (b * b) % p
      m = i
      iterations += 1
    end

    x
  end

  def self.pow_mod(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
    result = BigInt.new(1)
    base_copy = base % mod
    exp_copy = exp

    while exp_copy > 0
      result = (result * base_copy) % mod if exp_copy.odd?
      base_copy = (base_copy * base_copy) % mod
      exp_copy >>= 1
    end

    result
  end
end