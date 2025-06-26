require "../spec_helper"

describe Crypto::DH::DHParameters do
  describe "parameter validation" do
    it "validates correct parameters" do
      p = BigInt.new("23")  # Small prime for testing
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      params.valid?.should be_true
      params.p.should eq(p)
      params.g.should eq(g)
      params.bit_length.should eq(5)  # 23 in binary is 10111 (5 bits)
    end
    
    it "rejects invalid parameters" do
      # Invalid prime (even number)
      params1 = Crypto::DH::DHParameters.new(BigInt.new("24"), BigInt.new("5"))
      params1.valid?.should be_false
      
      # Invalid generator (too small)
      params2 = Crypto::DH::DHParameters.new(BigInt.new("23"), BigInt.new("1"))
      params2.valid?.should be_false
      
      # Invalid generator (too large)
      params3 = Crypto::DH::DHParameters.new(BigInt.new("23"), BigInt.new("25"))
      params3.valid?.should be_false
    end
    
    it "validates safe primes correctly" do
      # Test with a known safe prime: 23 = 2*11 + 1 (both 23 and 11 are prime)
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      params.safe_prime?.should be_true
      params.valid_generator_for_safe_prime?.should be_true
    end
    
    it "rejects non-safe primes" do
      # 17 is prime but not safe (17 = 2*8 + 1, but 8 is not prime)
      p = BigInt.new("17")
      g = BigInt.new("3")
      params = Crypto::DH::DHParameters.new(p, g)
      
      params.safe_prime?.should be_false
    end
  end
end

describe Crypto::DH::DHPublicKey do
  describe "public key operations" do
    it "creates valid public key" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      # Generate a valid public key value (g^x mod p)
      x = BigInt.new("6")  # private key
      y = (g ** x) % p     # public key = 5^6 mod 23 = 15625 mod 23 = 8
      
      public_key = Crypto::DH::DHPublicKey.new(y, params)
      public_key.valid?.should be_true
      public_key.y.should eq(y)
    end
    
    it "converts to and from bytes" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      y = BigInt.new("8")
      
      public_key = Crypto::DH::DHPublicKey.new(y, params)
      bytes = public_key.to_bytes
      
      reconstructed = Crypto::DH::DHPublicKey.from_bytes(bytes, params)
      reconstructed.y.should eq(public_key.y)
    end
    
    it "rejects invalid public key values" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      # Too small
      public_key1 = Crypto::DH::DHPublicKey.new(BigInt.new("1"), params)
      public_key1.valid?.should be_false
      
      # Too large
      public_key2 = Crypto::DH::DHPublicKey.new(BigInt.new("23"), params)
      public_key2.valid?.should be_false
    end
  end
end

describe Crypto::DH::DHPrivateKey do
  describe "private key operations" do
    it "creates valid private key and generates public key" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      x = BigInt.new("6")  # private key
      private_key = Crypto::DH::DHPrivateKey.new(x, params)
      
      private_key.valid?.should be_true
      private_key.x.should eq(x)
      
      public_key = private_key.public_key
      public_key.valid?.should be_true
      # 5^6 mod 23 = 15625 mod 23 = 8
      public_key.y.should eq(BigInt.new("8"))
    end
    
    it "computes shared secret correctly" do
      # Use larger prime for more realistic test
      p = BigInt.new("2357")  # A larger prime
      g = BigInt.new("2")
      params = Crypto::DH::DHParameters.new(p, g)
      
      # Alice's keys
      alice_private = BigInt.new("123")
      alice_key = Crypto::DH::DHPrivateKey.new(alice_private, params)
      alice_public = alice_key.public_key
      
      # Bob's keys  
      bob_private = BigInt.new("456")
      bob_key = Crypto::DH::DHPrivateKey.new(bob_private, params)
      bob_public = bob_key.public_key
      
      # Compute shared secrets
      alice_shared = alice_key.compute_shared_secret(bob_public)
      bob_shared = bob_key.compute_shared_secret(alice_public)
      
      # Should be the same
      alice_shared.should eq(bob_shared)
    end
    
    it "validates private key range" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      # Too small
      private_key1 = Crypto::DH::DHPrivateKey.new(BigInt.new("1"), params)
      private_key1.valid?.should be_false
      
      # Valid
      private_key2 = Crypto::DH::DHPrivateKey.new(BigInt.new("6"), params)
      private_key2.valid?.should be_true
      
      # Too large (for safe prime, should be < q where q = (p-1)/2)
      private_key3 = Crypto::DH::DHPrivateKey.new(BigInt.new("15"), params)
      private_key3.valid?.should be_false
    end
    
    it "clears private key securely" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      params = Crypto::DH::DHParameters.new(p, g)
      
      private_key = Crypto::DH::DHPrivateKey.new(BigInt.new("6"), params)
      private_key.x.should eq(BigInt.new("6"))
      
      private_key.clear!
      private_key.x.should eq(BigInt.new("0"))
    end
  end
end

describe Crypto::DH::DiffieHellman do
  describe "key exchange operations" do
    it "generates keypair successfully" do
      p = BigInt.new("2357")  # Larger prime for testing
      g = BigInt.new("2")
      dh = Crypto::DH::DiffieHellman.new(p, g)
      
      private_key, public_key = dh.generate_keypair!
      
      private_key.valid?.should be_true
      public_key.valid?.should be_true
      public_key.should eq(private_key.public_key)
    end
    
    it "computes shared secret with bytes" do
      p = BigInt.new("2357")
      g = BigInt.new("2")
      
      # Alice
      alice_dh = Crypto::DH::DiffieHellman.new(p, g)
      alice_private, alice_public = alice_dh.generate_keypair!
      
      # Bob  
      bob_dh = Crypto::DH::DiffieHellman.new(p, g)
      bob_private, bob_public = bob_dh.generate_keypair!
      
      # Exchange public keys as bytes
      alice_public_bytes = alice_public.to_bytes
      bob_public_bytes = bob_public.to_bytes
      
      # Compute shared secrets
      alice_shared = alice_dh.compute_shared_secret(bob_public_bytes)
      bob_shared = bob_dh.compute_shared_secret(alice_public_bytes)
      
      alice_shared.should eq(bob_shared)
    end
    
    it "validates parameters during creation" do
      # Invalid parameters should raise
      expect_raises(Exception, "Invalid DH parameters") do
        Crypto::DH::DiffieHellman.new(BigInt.new("24"), BigInt.new("5"))  # Even "prime"
      end
    end
    
    it "provides key size information" do
      p = BigInt.new("2357")
      g = BigInt.new("2")
      dh = Crypto::DH::DiffieHellman.new(p, g)
      
      dh.key_size.should eq(p.bit_length)
    end
    
    it "validates parameter security" do
      # Small parameters should fail validation
      small_params = Crypto::DH::DHParameters.new(BigInt.new("23"), BigInt.new("5"))
      Crypto::DH::DiffieHellman.validate_parameters(small_params, 2048).should be_false
      
      # Non-safe prime should fail
      non_safe_params = Crypto::DH::DHParameters.new(BigInt.new("17"), BigInt.new("3"))
      Crypto::DH::DiffieHellman.validate_parameters(non_safe_params, 10).should be_false
    end
  end
  
  describe "error handling" do
    it "raises error when computing shared secret without private key" do
      p = BigInt.new("23")
      g = BigInt.new("5")
      dh = Crypto::DH::DiffieHellman.new(p, g)
      
      # Try to compute without generating keypair
      expect_raises(Exception, "No private key available") do
        dh.compute_shared_secret(Bytes.new(1))
      end
    end
    
    it "raises error for parameter mismatch" do
      p1 = BigInt.new("23")
      p2 = BigInt.new("29")  # Different prime
      g = BigInt.new("5")
      
      dh1 = Crypto::DH::DiffieHellman.new(p1, g)
      params2 = Crypto::DH::DHParameters.new(p2, g)
      
      private_key = Crypto::DH::DHPrivateKey.new(BigInt.new("6"), params2)
      
      expect_raises(Exception, "Parameter mismatch") do
        dh1.private_key = private_key
      end
    end
  end
end