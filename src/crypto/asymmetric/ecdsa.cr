require "big"
require "random"
require "../base/asymmetric_algorithm"
require "./ec"
require "./p256"
require "./p384"
require "../hashes/sha256"
require "../hashes/sha3"

module Crypto::Asymmetric
  # ECDSA key pair
  struct ECDSAKeyPair
    property private_key : BigInt
    property public_key : ECPoint
    property curve : EllipticCurve

    def initialize(@private_key : BigInt, @public_key : ECPoint, @curve : EllipticCurve)
    end

    # Create key pair from private key
    def self.from_private_key(private_key : BigInt, curve : EllipticCurve) : ECDSAKeyPair
      public_key = curve.derive_public_key(private_key)
      new(private_key, public_key, curve)
    end

    # Generate a new key pair
    def self.generate(curve : EllipticCurve) : ECDSAKeyPair
      private_key = curve.generate_private_key
      from_private_key(private_key, curve)
    end

    # Get public key bytes (uncompressed format)
    def public_key_bytes : Bytes
      field_size = (@curve.key_size + 7) // 8
      @public_key.to_bytes_uncompressed(field_size)
    end

    # Get public key bytes (compressed format)
    def public_key_bytes_compressed : Bytes
      field_size = (@curve.key_size + 7) // 8
      @public_key.to_bytes_compressed(field_size)
    end

    # Get key size in bits
    def key_size : Int32
      @curve.key_size
    end
  end

  # ECDSA implementation
  class ECDSA < SignatureAlgorithm
    @key_pair : ECDSAKeyPair
    @hash_function : (Bytes) -> Bytes

    def initialize(@key_pair : ECDSAKeyPair, @hash_function : (Bytes) -> Bytes)
    end

    # Create ECDSA instance for P-256 with SHA-256
    def self.p256_sha256(private_key : BigInt? = nil) : ECDSA
      curve = P256.get
      key_pair = private_key ? ECDSAKeyPair.from_private_key(private_key, curve) : ECDSAKeyPair.generate(curve)
      hash_func = ->(data : Bytes) {
        sha256 = Crypto::Hashes::Sha256.new
        sha256.hash_bytes(data)
      }
      new(key_pair, hash_func)
    end

    # Create ECDSA instance for P-384 with SHA-384
    def self.p384_sha384(private_key : BigInt? = nil) : ECDSA
      curve = P384.get
      key_pair = private_key ? ECDSAKeyPair.from_private_key(private_key, curve) : ECDSAKeyPair.generate(curve)
      hash_func = ->(data : Bytes) {
        sha384 = Crypto::Hashes::SHA3_384.new
        sha384.hash_bytes(data)
      }
      new(key_pair, hash_func)
    end

    # Create ECDSA instance from key pair
    def self.from_key_pair(key_pair : ECDSAKeyPair, hash_function : (Bytes) -> Bytes) : ECDSA
      new(key_pair, hash_function)
    end

    # Sign data
    def sign(data : Bytes) : Bytes
      # Hash the message
      hash = @hash_function.call(data)
      sign_hash(hash)
    end

    # Sign hash directly
    def sign_hash(hash : Bytes) : Bytes
      # Convert hash to integer
      e = BigInt.new(0)
      hash.each { |byte| e = (e << 8) | byte.to_big_i }
      curve = @key_pair.curve

      # Ensure e is within the field
      e = e % curve.n if e >= curve.n

      # Generate signature with retry logic
      max_attempts = 10
      max_attempts.times do
        # Generate random k (1 <= k < n)
        k = curve.generate_private_key

        # Calculate point (x1, y1) = k * G
        point = curve.scalar_multiply(k, curve.g)

        # Calculate r = x1 mod n
        r = point.x % curve.n
        next if r == 0  # Invalid, try again

        # Calculate s = k^(-1) * (e + r * d) mod n
        k_inv = Crypto.mod_inverse(k, curve.n)
        next if k_inv == 0  # Invalid, try again

        s = (k_inv * (e + r * @key_pair.private_key)) % curve.n
        next if s == 0  # Invalid, try again

        # Valid signature
        signature = ECDSASignature.new(r, s)
        return signature.to_der
      end

      raise "Failed to generate valid ECDSA signature after #{max_attempts} attempts"
    end

    # Verify signature
    def verify(data : Bytes, signature : Bytes) : Bool
      # Hash the message
      hash = @hash_function.call(data)
      verify_hash(hash, signature)
    end

    # Verify hash directly
    def verify_hash(hash : Bytes, signature : Bytes) : Bool
      begin
        # Parse DER signature
        sig = ECDSASignature.from_der(signature)
        return verify_hash_signature(hash, sig.r, sig.s)
      rescue
        return false
      end
    end

    # Verify hash with r, s components
    def verify_hash_signature(hash : Bytes, r : BigInt, s : BigInt) : Bool
      curve = @key_pair.curve

      # Check r and s are valid
      return false if r <= 0 || r >= curve.n
      return false if s <= 0 || s >= curve.n

      # Convert hash to integer
      e = BigInt.new(0)
      hash.each { |byte| e = (e << 8) | byte.to_big_i }
      e = e % curve.n if e >= curve.n

      # Calculate w = s^(-1) mod n
      w = Crypto.mod_inverse(s, curve.n)

      # Calculate u1 = e * w mod n and u2 = r * w mod n
      u1 = (e * w) % curve.n
      u2 = (r * w) % curve.n

      # Calculate point (x1, y1) = u1 * G + u2 * Q
      point1 = curve.scalar_multiply(u1, curve.g)
      point2 = curve.scalar_multiply(u2, @key_pair.public_key)
      point = point1.add(point2, curve)

      # Check if point is at infinity
      return false if point.infinity?

      # Calculate v = x1 mod n
      v = point.x % curve.n

      # Signature is valid if v == r
      v == r
    end

    # Get public key as bytes
    def public_key : Bytes
      @key_pair.public_key_bytes
    end

    # Get compressed public key
    def public_key_compressed : Bytes
      @key_pair.public_key_bytes_compressed
    end

    # Get key size in bits
    def key_size : Int32
      @key_pair.key_size
    end

    # Get curve name
    def curve_name : String
      @key_pair.curve.name
    end

    # Get the private key (be careful with exposure!)
    def private_key : BigInt
      @key_pair.private_key
    end

    # Get the key pair
    def key_pair : ECDSAKeyPair
      @key_pair
    end

    # Import public key from bytes
    def self.import_public_key(bytes : Bytes, curve : EllipticCurve) : ECPoint
      ECPoint.from_bytes(bytes, curve)
    end

    # Import private key and create key pair
    def self.import_private_key(private_key_bytes : Bytes, curve : EllipticCurve) : ECDSAKeyPair
      private_key = BigInt.new(0)
      private_key_bytes.each { |byte| private_key = (private_key << 8) | byte.to_big_i }
      ECDSAKeyPair.from_private_key(private_key, curve)
    end

    # Export private key as bytes
    def export_private_key : Bytes
      field_size = (@key_pair.key_size + 7) // 8
      result = Bytes.new(field_size)
      temp = @key_pair.private_key
      (field_size - 1).downto(0) do |i|
        result[i] = (temp & 0xff).to_u8
        temp >>= 8
      end
      result
    end

    
    # Recover public key from signature (used in Bitcoin/Ethereum)
    def recover_public_key(hash : Bytes, signature : Bytes, recovery_id : Int32) : ECPoint?
      begin
        sig = ECDSASignature.from_der(signature)
        return recover_public_key_from_rs(hash, sig.r, sig.s, recovery_id)
      rescue
        return nil
      end
    end

    private def recover_public_key_from_rs(hash : Bytes, r : BigInt, s : BigInt, recovery_id : Int32) : ECPoint?
      curve = @key_pair.curve
      e = bytes_to_bigint(hash)
      e = e % curve.n if e >= curve.n

      # Calculate r inverse
      r_inv = Crypto.mod_inverse(r, curve.n)

      # Calculate signature R point
      x = r + (recovery_id // 2) * curve.n

      # Solve for y coordinate
      alpha = (x * x * x + curve.a * x + curve.b) % curve.p
      beta = Crypto.mod_sqrt(alpha, curve.p)
      return nil if beta.nil?

      y = (recovery_id % 2) == 1 ? curve.p - beta : beta
      r_point = ECPoint.new(x, y)

      # Calculate public key Q = r^(-1) * (s * R - e * G)
      s_r = (s * r_inv) % curve.n
      e_r = (e * r_inv) % curve.n

      neg_e_r = (curve.n - e_r) % curve.n

      point1 = curve.scalar_multiply(s_r, r_point)
      point2 = curve.scalar_multiply(neg_e_r, curve.g)
      q = point1.add(point2, curve)

      # Verify the recovered public key
      return nil if q.infinity? || !curve.point_on_curve?(q)

      # Verify the signature with the recovered key
      if verify_with_public_key(hash, r, s, q)
        return q
      end

      nil
    end

    private def verify_with_public_key(hash : Bytes, r : BigInt, s : BigInt, public_key : ECPoint) : Bool
      curve = @key_pair.curve

      return false if r <= 0 || r >= curve.n
      return false if s <= 0 || s >= curve.n

      e = bytes_to_bigint(hash)
      e = e % curve.n if e >= curve.n

      w = Crypto.mod_inverse(s, curve.n)
      u1 = (e * w) % curve.n
      u2 = (r * w) % curve.n

      point1 = curve.scalar_multiply(u1, curve.g)
      point2 = curve.scalar_multiply(u2, public_key)
      point = point1.add(point2, curve)

      return false if point.infinity?

      v = point.x % curve.n
      v == r
    end

      end
end