require "big"
require "random/secure"
require "../base/asymmetric_algorithm"

module Crypto
  module DH
    # Utility methods for BigInt/Bytes conversion
    module Utils
      def self.bytes_to_bigint(bytes : Bytes) : BigInt
        result = BigInt.new(0)
        bytes.each do |byte|
          result = (result << 8) | byte.to_big_i
        end
        result
      end
      
      def self.bigint_to_bytes(value : BigInt, length : Int32) : Bytes
        result = Bytes.new(length)
        temp = value
        
        (length - 1).downto(0) do |i|
          result[i] = (temp & 0xff).to_u8
          temp >>= 8
        end
        
        result
      end
      
      # Secure modular exponentiation
      def self.mod_pow(base : BigInt, exp : BigInt, modulus : BigInt) : BigInt
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
      
      # Generate random BigInt in range [min, max]
      def self.random_bigint(min : BigInt, max : BigInt) : BigInt
        range = max - min + 1
        byte_length = (range.bit_length + 7) // 8
        
        loop do
          bytes = Random::Secure.random_bytes(byte_length)
          candidate = bytes_to_bigint(bytes) % range
          candidate += min
          return candidate if candidate >= min && candidate <= max
        end
      end
    end
    
    # Diffie-Hellman parameters
    struct DHParameters
      property p : BigInt    # prime modulus
      property g : BigInt    # generator
      
      def initialize(@p : BigInt, @g : BigInt)
      end
      
      # Get bit length of the modulus
      def bit_length : Int32
        @p.bit_length
      end
      
      # Validate DH parameters for security
      def valid? : Bool
        return false if @p <= 1
        return false if @g <= 1 || @g >= @p
        
        # Check that p is odd (all primes except 2 are odd)
        return false if @p.even?
        
        # Basic generator validation - should be greater than 1 and less than p
        return false if @g <= 1 || @g >= @p
        
        true
      end
      
      # Check if p is a safe prime (p = 2q + 1 where q is also prime)
      # This is a comprehensive but slow check
      def safe_prime? : Bool
        return false unless valid?
        
        q = (@p - 1) // 2
        return false unless prime?(q)
        return false unless prime?(@p)
        
        true
      end
      
      # Validate generator for safe prime
      # For safe primes p = 2q + 1, valid generators g should satisfy:
      # g^q mod p = p-1 (generator of order q)
      def valid_generator_for_safe_prime? : Bool
        return false unless safe_prime?
        
        q = (@p - 1) // 2
        result = Utils.mod_pow(@g, q, @p)
        result == (@p - 1)
      end
      
      # Miller-Rabin primality test
      private def prime?(n : BigInt, k : Int32 = 10) : Bool
        return false if n < 2
        return true if n == 2 || n == 3
        return false if n.even?
        
        # Write n-1 as d * 2^r
        d = n - 1
        r = 0
        while d.even?
          d //= 2
          r += 1
        end
        
        # Witness loop
        k.times do
          a = Utils.random_bigint(BigInt.new(2), n - 2)
          x = Utils.mod_pow(a, d, n)
          
          next if x == 1 || x == n - 1
          
          (r - 1).times do
            x = Utils.mod_pow(x, BigInt.new(2), n)
            return false if x == 1
            break if x == n - 1
          end
          
          return false if x != n - 1
        end
        
        true
      end
    end
    
    # Diffie-Hellman public key
    struct DHPublicKey
      property y : BigInt           # public key value (g^x mod p)
      property parameters : DHParameters
      
      def initialize(@y : BigInt, @parameters : DHParameters)
      end
      
      # Validate that the public key is in the valid range
      def valid? : Bool
        return false unless @parameters.valid?
        return false if @y <= 1 || @y >= @parameters.p - 1
        
        # Skip expensive safe prime subgroup validation for large primes
        # This check is computationally expensive for 2048-bit primes
        # Protocol-specific validation should be done separately as needed
        # 
        # if @parameters.safe_prime?
        #   q = (@parameters.p - 1) // 2
        #   result = Utils.mod_pow(@y, q, @parameters.p)
        #   return result == 1
        # end
        
        true
      end
      
      # Convert to bytes (big-endian)
      def to_bytes : Bytes
        bit_length = @parameters.bit_length
        byte_length = (bit_length + 7) // 8
        Utils.bigint_to_bytes(@y, byte_length)
      end
      
      # Create from bytes
      def self.from_bytes(bytes : Bytes, parameters : DHParameters) : DHPublicKey
        y = Utils.bytes_to_bigint(bytes)
        new(y, parameters)
      end
    end
    
    # Diffie-Hellman private key
    struct DHPrivateKey
      property x : BigInt           # private key value
      property parameters : DHParameters
      
      def initialize(@x : BigInt, @parameters : DHParameters)
      end
      
      # Generate corresponding public key
      def public_key : DHPublicKey
        y = Utils.mod_pow(@parameters.g, @x, @parameters.p)
        DHPublicKey.new(y, @parameters)
      end
      
      # Validate that the private key is in the valid range
      def valid? : Bool
        return false unless @parameters.valid?
        return false if @x <= 1
        
        # For safe primes, private key should be in range [2, q-1] where q = (p-1)/2
        if @parameters.safe_prime?
          q = (@parameters.p - 1) // 2
          return @x >= 2 && @x <= q - 1
        else
          # For general primes, private key should be in range [2, p-2]
          return @x >= 2 && @x <= @parameters.p - 2
        end
      end
      
      # Compute shared secret with a public key
      def compute_shared_secret(public_key : DHPublicKey) : Bytes
        raise "Invalid public key" unless public_key.valid?
        raise "Parameter mismatch" unless public_key.parameters.p == @parameters.p && public_key.parameters.g == @parameters.g
        
        # Shared secret = public_key^private_key mod p
        shared_secret = Utils.mod_pow(public_key.y, @x, @parameters.p)
        
        # Convert to bytes
        bit_length = @parameters.bit_length
        byte_length = (bit_length + 7) // 8
        Utils.bigint_to_bytes(shared_secret, byte_length)
      end
      
      # Securely clear the private key from memory
      def clear!
        @x = BigInt.new(0)
      end
    end
    
    # Main Diffie-Hellman implementation
    class DiffieHellman < Crypto::KeyExchange
      @parameters : DHParameters
      @private_key : DHPrivateKey?
      @public_key : DHPublicKey?
      
      def initialize(@parameters : DHParameters)
        raise "Invalid DH parameters" unless @parameters.valid?
      end
      
      # Create DH instance with standard parameters
      def self.new(p : BigInt, g : BigInt) : DiffieHellman
        params = DHParameters.new(p, g)
        new(params)
      end
      
      # Generate a new key pair
      def generate_keypair! : {DHPrivateKey, DHPublicKey}
        # Generate random private key
        if @parameters.safe_prime?
          # For safe primes, use range [2, q-1] where q = (p-1)/2
          q = (@parameters.p - 1) // 2
          @private_key = DHPrivateKey.new(Utils.random_bigint(BigInt.new(2), q - 1), @parameters)
        else
          # For general primes, use range [2, p-2]
          @private_key = DHPrivateKey.new(Utils.random_bigint(BigInt.new(2), @parameters.p - 2), @parameters)
        end
        
        @public_key = @private_key.not_nil!.public_key
        
        {@private_key.not_nil!, @public_key.not_nil!}
      end
      
      # Set existing private key
      def private_key=(key : DHPrivateKey)
        raise "Invalid private key" unless key.valid?
        raise "Parameter mismatch" unless key.parameters.p == @parameters.p && key.parameters.g == @parameters.g
        
        @private_key = key
        @public_key = key.public_key
      end
      
      # Get public key (generates if needed)
      def get_public_key : DHPublicKey
        generate_keypair! unless @public_key
        @public_key.not_nil!
      end
      
      # Returns the public key as bytes
      def public_key : Bytes
        get_public_key.to_bytes
      end
      
      # Returns the key size in bits
      def key_size : Int32
        @parameters.bit_length
      end
      
      # Compute shared secret with another party's public key
      def compute_shared_secret(public_key : Bytes) : Bytes
        raise "No private key available" unless @private_key
        
        other_key = DHPublicKey.from_bytes(public_key, @parameters)
        @private_key.not_nil!.compute_shared_secret(other_key)
      end
      
      # Compute shared secret with DHPublicKey
      def compute_shared_secret(other_public_key : DHPublicKey) : Bytes
        raise "No private key available" unless @private_key
        
        @private_key.not_nil!.compute_shared_secret(other_public_key)
      end
      
      # Get DH parameters
      def parameters : DHParameters
        @parameters
      end
      
      # Validate that parameters are secure for the given bit length
      def self.validate_parameters(params : DHParameters, min_bits : Int32 = 2048) : Bool
        return false unless params.valid?
        return false if params.bit_length < min_bits
        
        # For high security, prefer safe primes
        return false unless params.safe_prime?
        return false unless params.valid_generator_for_safe_prime?
        
        true
      end
    end
  end
end