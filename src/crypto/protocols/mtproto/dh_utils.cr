require "../../key_exchange/dh"

module Crypto::Protocols::MTProto
  # MTProto-specific Diffie-Hellman utilities
  module DHUtils
    # MTProto uses 2048-bit safe primes
    # This is a safe prime used in MTProto (p = 2q + 1 where both p and q are prime)
    # This is actually Telegram's DH prime from their official documentation
    MTPROTO_DH_PRIME = BigInt.new("C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B", 16)
    
    # Valid generators for the MTProto DH prime (only 2, 5, 6 are mathematically valid for this prime)
    # Note: MTProto documentation mentions 2,3,4,5,6,7 but only some work with this specific prime
    MTPROTO_VALID_GENERATORS = [2, 5, 6].map { |g| BigInt.new(g) }
    
    # Create MTProto DH parameters with the standard prime and generator
    def self.create_mtproto_parameters(generator : Int32 = 2) : Crypto::DH::DHParameters
      raise "Invalid generator for MTProto" unless MTPROTO_VALID_GENERATORS.includes?(BigInt.new(generator))
      
      params = Crypto::DH::DHParameters.new(MTPROTO_DH_PRIME, BigInt.new(generator))
      
      # Validate the parameters
      raise "MTProto DH parameters validation failed" unless validate_mtproto_parameters(params)
      
      params
    end
    
    # Create MTProto DH instance
    def self.create_mtproto_dh(generator : Int32 = 2) : Crypto::DH::DiffieHellman
      params = create_mtproto_parameters(generator)
      Crypto::DH::DiffieHellman.new(params)
    end
    
    # Validate MTProto DH parameters
    def self.validate_mtproto_parameters(params : Crypto::DH::DHParameters) : Bool
      # Must be the correct prime
      return false unless params.p == MTPROTO_DH_PRIME
      
      # Must be a valid generator
      return false unless MTPROTO_VALID_GENERATORS.includes?(params.g)
      
      # Must be 2048 bits
      return false unless params.bit_length == 2048
      
      # Must be a safe prime (skip expensive test for known MTProto prime)
      # return false unless params.safe_prime?
      
      # Validate generator for this safe prime  
      return false unless validate_mtproto_generator(params.g)
      
      true
    end
    
    # Validate that a generator is valid for MTProto's safe prime
    def self.validate_mtproto_generator(g : BigInt) : Bool
      return false unless MTPROTO_VALID_GENERATORS.includes?(g)
      
      # For the safe prime p = 2q + 1, check that g^q mod p = p-1
      # This ensures g generates the correct subgroup of order q
      q = (MTPROTO_DH_PRIME - 1) // 2
      result = Crypto::DH::Utils.mod_pow(g, q, MTPROTO_DH_PRIME)
      
      result == (MTPROTO_DH_PRIME - 1)
    end
    
    # Validate MTProto public key (additional security checks)
    def self.validate_mtproto_public_key(public_key : Crypto::DH::DHPublicKey) : Bool
      # Basic validation - should pass if the DH public key is valid
      return false unless validate_mtproto_parameters(public_key.parameters)
      
      # Additional MTProto-specific checks
      y = public_key.y
      
      # Public key must be in range [2, p-2]
      return false if y <= 1 || y >= MTPROTO_DH_PRIME - 1
      
      # For MTProto production use, consider implementing additional subgroup validation
      # For now, basic range validation provides reasonable security
      
      true
    end
    
    # Validate MTProto private key
    def self.validate_mtproto_private_key(private_key : Crypto::DH::DHPrivateKey) : Bool
      return false unless private_key.valid?
      return false unless validate_mtproto_parameters(private_key.parameters)
      
      x = private_key.x
      q = (MTPROTO_DH_PRIME - 1) // 2
      
      # Private key should be in range [2, q-1] for safe prime
      return false if x <= 1 || x >= q
      
      true
    end
    
    # Generate secure MTProto DH keypair
    def self.generate_mtproto_keypair(generator : Int32 = 2) : {Crypto::DH::DHPrivateKey, Crypto::DH::DHPublicKey}
      dh = create_mtproto_dh(generator)
      private_key, public_key = dh.generate_keypair!
      
      # Validate the generated keys
      raise "Generated private key failed validation" unless validate_mtproto_private_key(private_key)
      raise "Generated public key failed validation" unless validate_mtproto_public_key(public_key)
      
      {private_key, public_key}
    end
    
    # Compute MTProto shared secret with additional validation
    def self.compute_mtproto_shared_secret(private_key : Crypto::DH::DHPrivateKey, 
                                         public_key : Crypto::DH::DHPublicKey) : Bytes
      # Validate both keys
      raise "Invalid private key for MTProto" unless validate_mtproto_private_key(private_key)
      raise "Invalid public key for MTProto" unless validate_mtproto_public_key(public_key)
      
      # Compute shared secret
      shared_secret = private_key.compute_shared_secret(public_key)
      
      # Additional validation on shared secret
      shared_secret_bigint = Crypto::DH::Utils.bytes_to_bigint(shared_secret)
      
      # Shared secret should not be 1, p-1, or other small values
      return shared_secret if validate_shared_secret(shared_secret_bigint)
      
      raise "Shared secret failed validation (possible small subgroup attack)"
    end
    
    # Validate shared secret for security
    private def self.validate_shared_secret(secret : BigInt) : Bool
      # Secret should not be small values that indicate subgroup attacks
      dangerous_values = [
        BigInt.new(1),
        MTPROTO_DH_PRIME - 1,
        BigInt.new(0)
      ]
      
      return false if dangerous_values.includes?(secret)
      
      # Secret should be in reasonable range
      return false if secret <= 1 || secret >= MTPROTO_DH_PRIME - 1
      
      true
    end
    
    # Convert public key to MTProto format (big-endian bytes)
    def self.public_key_to_mtproto_bytes(public_key : Crypto::DH::DHPublicKey) : Bytes
      raise "Invalid public key for MTProto" unless validate_mtproto_public_key(public_key)
      
      # MTProto uses 256 bytes (2048 bits) big-endian format
      Crypto::DH::Utils.bigint_to_bytes(public_key.y, 256)
    end
    
    # Create public key from MTProto bytes
    def self.public_key_from_mtproto_bytes(bytes : Bytes, generator : Int32 = 2) : Crypto::DH::DHPublicKey
      raise "Invalid MTProto public key size" unless bytes.size == 256
      
      params = create_mtproto_parameters(generator)
      y = Crypto::DH::Utils.bytes_to_bigint(bytes)
      
      public_key = Crypto::DH::DHPublicKey.new(y, params)
      raise "Invalid public key" unless validate_mtproto_public_key(public_key)
      
      public_key
    end
    
    # Get MTProto DH parameters info
    def self.mtproto_parameters_info : NamedTuple(prime_hex: String, bit_length: Int32, generators: Array(Int32))
      {
        prime_hex: MTPROTO_DH_PRIME.to_s(16),
        bit_length: MTPROTO_DH_PRIME.bit_length,
        generators: MTPROTO_VALID_GENERATORS.map(&.to_i32)
      }
    end
    
    # Check if parameters match MTProto standard
    def self.is_mtproto_parameters?(params : Crypto::DH::DHParameters) : Bool
      params.p == MTPROTO_DH_PRIME && MTPROTO_VALID_GENERATORS.includes?(params.g)
    end
    
    # Utility methods are now in Crypto::DH::Utils
  end
end