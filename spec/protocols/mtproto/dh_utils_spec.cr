require "../../spec_helper"

describe Crypto::Protocols::MTProto::DHUtils do
  describe "MTProto DH parameters" do
    it "creates valid MTProto parameters" do
      params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters
      
      params.valid?.should be_true
      params.bit_length.should eq(2048)
      params.p.should eq(Crypto::Protocols::MTProto::DHUtils::MTPROTO_DH_PRIME)
      params.g.should eq(BigInt.new(2))  # Default generator
    end
    
    it "supports all valid generators" do
      [2, 5, 6].each do |generator|
        params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters(generator)
        
        params.valid?.should be_true
        params.g.should eq(BigInt.new(generator))
        Crypto::Protocols::MTProto::DHUtils.validate_mtproto_generator(params.g).should be_true
      end
    end
    
    it "rejects invalid generators" do
      [1, 3, 4, 7, 8, 9, 10].each do |invalid_generator|
        expect_raises(Exception, "Invalid generator for MTProto") do
          Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters(invalid_generator)
        end
      end
    end
    
    it "validates MTProto parameters correctly" do
      # Valid parameters
      valid_params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters(5)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_parameters(valid_params).should be_true
      
      # Wrong prime
      wrong_prime_params = Crypto::DH::DHParameters.new(BigInt.new("23"), BigInt.new("3"))
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_parameters(wrong_prime_params).should be_false
      
      # Wrong generator
      wrong_gen_params = Crypto::DH::DHParameters.new(
        Crypto::Protocols::MTProto::DHUtils::MTPROTO_DH_PRIME, 
        BigInt.new("8")
      )
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_parameters(wrong_gen_params).should be_false
    end
  end
  
  describe "MTProto DH instance creation" do
    it "creates valid MTProto DH instance" do
      dh = Crypto::Protocols::MTProto::DHUtils.create_mtproto_dh
      
      dh.key_size.should eq(2048)
      dh.parameters.p.should eq(Crypto::Protocols::MTProto::DHUtils::MTPROTO_DH_PRIME)
      dh.parameters.g.should eq(BigInt.new(2))
    end
    
    it "creates DH instance with different generators" do
      [2, 5, 6].each do |generator|
        dh = Crypto::Protocols::MTProto::DHUtils.create_mtproto_dh(generator)
        dh.parameters.g.should eq(BigInt.new(generator))
      end
    end
  end
  
  describe "MTProto key generation and validation" do
    it "generates valid MTProto keypair" do
      private_key, public_key = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(private_key).should be_true
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_public_key(public_key).should be_true
      
      # Keys should match
      public_key.should eq(private_key.public_key)
    end
    
    it "generates different keypairs each time" do
      keypair1 = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      keypair2 = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Private keys should be different
      keypair1[0].x.should_not eq(keypair2[0].x)
      
      # Public keys should be different
      keypair1[1].y.should_not eq(keypair2[1].y)
    end
    
    it "validates private key range correctly" do
      params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters
      q = (params.p - 1) // 2
      
      # Valid private key
      valid_private = Crypto::DH::DHPrivateKey.new(BigInt.new(1000), params)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(valid_private).should be_true
      
      # Invalid private key (too small)
      invalid_small = Crypto::DH::DHPrivateKey.new(BigInt.new(1), params)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(invalid_small).should be_false
      
      # Invalid private key (too large)
      invalid_large = Crypto::DH::DHPrivateKey.new(q, params)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(invalid_large).should be_false
    end
    
    it "validates public key subgroup membership" do
      params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters
      
      # Generate a valid public key
      private_key, public_key = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_public_key(public_key).should be_true
      
      # Create an invalid public key (y = p - 1)
      invalid_public = Crypto::DH::DHPublicKey.new(params.p - 1, params)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_public_key(invalid_public).should be_false
    end
  end
  
  describe "MTProto shared secret computation" do
    it "computes shared secret correctly" do
      # Generate Alice's keypair
      alice_private, alice_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Generate Bob's keypair
      bob_private, bob_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Compute shared secrets
      alice_shared = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(alice_private, bob_public)
      bob_shared = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(bob_private, alice_public)
      
      # Should be identical
      alice_shared.should eq(bob_shared)
      
      # Should be 256 bytes (2048 bits)
      alice_shared.size.should eq(256)
    end
    
    it "validates shared secret security" do
      # This test ensures the shared secret validation catches dangerous values
      alice_private, alice_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      bob_private, bob_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Normal case should work
      shared_secret = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(alice_private, bob_public)
      shared_secret.size.should eq(256)
      
      # Shared secret should not be all zeros or other dangerous values
      shared_secret.should_not eq(Bytes.new(256, 0))
      shared_secret.should_not eq(Bytes.new(256, 0xFF))
    end
    
    it "rejects invalid keys for shared secret computation" do
      # Valid keys
      alice_private, alice_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Invalid public key (wrong parameters)
      wrong_params = Crypto::DH::DHParameters.new(BigInt.new("23"), BigInt.new("5"))
      invalid_public = Crypto::DH::DHPublicKey.new(BigInt.new("8"), wrong_params)
      
      expect_raises(Exception, "Invalid public key for MTProto") do
        Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(alice_private, invalid_public)
      end
    end
  end
  
  describe "MTProto byte format conversion" do
    it "converts public key to MTProto bytes format" do
      private_key, public_key = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(public_key)
      
      # Should be 256 bytes (2048 bits)
      bytes.size.should eq(256)
      
      # Should not be all zeros
      bytes.should_not eq(Bytes.new(256, 0))
    end
    
    it "converts MTProto bytes back to public key" do
      private_key, original_public_key = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Convert to bytes and back
      bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(original_public_key)
      reconstructed_public_key = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(bytes)
      
      # Should be identical
      reconstructed_public_key.y.should eq(original_public_key.y)
      reconstructed_public_key.parameters.p.should eq(original_public_key.parameters.p)
      reconstructed_public_key.parameters.g.should eq(original_public_key.parameters.g)
    end
    
    it "rejects invalid MTProto byte sizes" do
      expect_raises(Exception, "Invalid MTProto public key size") do
        Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(Bytes.new(255))  # Wrong size
      end
      
      expect_raises(Exception, "Invalid MTProto public key size") do
        Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(Bytes.new(257))  # Wrong size
      end
    end
  end
  
  describe "MTProto generator validation" do
    it "validates all official MTProto generators" do
      [2, 5, 6].each do |generator|
        result = Crypto::Protocols::MTProto::DHUtils.validate_mtproto_generator(BigInt.new(generator))
        result.should be_true
      end
    end
    
    it "rejects invalid generators" do
      [1, 3, 4, 7, 8, 9, 10, 0, -1].each do |invalid_generator|
        result = Crypto::Protocols::MTProto::DHUtils.validate_mtproto_generator(BigInt.new(invalid_generator))
        result.should be_false
      end
    end
    
    it "validates generator mathematical properties" do
      # For MTProto's safe prime p = 2q + 1, valid generator g should satisfy:
      # g^q mod p = p-1
      [2, 5, 6].each do |generator|
        g = BigInt.new(generator)
        p = Crypto::Protocols::MTProto::DHUtils::MTPROTO_DH_PRIME
        q = (p - 1) // 2
        
        # This is the mathematical validation that MTProto requires
        result = Crypto::DH::Utils.mod_pow(g, q, p)
        result.should eq(p - 1)
      end
    end
  end
  
  describe "MTProto parameters info and utilities" do
    it "provides correct parameter information" do
      info = Crypto::Protocols::MTProto::DHUtils.mtproto_parameters_info
      
      info[:bit_length].should eq(2048)
      info[:generators].should eq([2, 5, 6])
      info[:prime_hex].should be_a(String)
      info[:prime_hex].size.should be > 500  # 2048-bit prime in hex
    end
    
    it "identifies MTProto parameters correctly" do
      # MTProto parameters
      mtproto_params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters
      Crypto::Protocols::MTProto::DHUtils.is_mtproto_parameters?(mtproto_params).should be_true
      
      # Non-MTProto parameters
      other_params = Crypto::DH::DHParameters.new(BigInt.new("23"), BigInt.new("5"))
      Crypto::Protocols::MTProto::DHUtils.is_mtproto_parameters?(other_params).should be_false
    end
  end
  
  describe "full MTProto DH exchange simulation" do
    it "performs complete DH exchange like Telegram would" do
      # Client (user) generates keypair
      client_private, client_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Server generates keypair
      server_private, server_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
      
      # Convert public keys to MTProto byte format (as would be sent over network)
      client_public_bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(client_public)
      server_public_bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(server_public)
      
      # Reconstruct public keys from bytes
      client_public_received = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(client_public_bytes)
      server_public_received = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(server_public_bytes)
      
      # Compute shared secrets
      client_shared = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(client_private, server_public_received)
      server_shared = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(server_private, client_public_received)
      
      # Verify they match
      client_shared.should eq(server_shared)
      
      # Verify proper size
      client_shared.size.should eq(256)
      
      # Verify not trivial values
      client_shared.should_not eq(Bytes.new(256, 0))
      client_shared.should_not eq(Bytes.new(256, 0xFF))
    end
    
    it "handles different generators in the same exchange" do
      # Both parties must use the same generator
      client_private, client_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair(5)
      server_private, server_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair(5)
      
      # Should work fine
      shared_secret = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(client_private, server_public)
      shared_secret.size.should eq(256)
      
      # Both should have same generator
      client_public.parameters.g.should eq(BigInt.new(5))
      server_public.parameters.g.should eq(BigInt.new(5))
    end
  end
  
  describe "security edge cases" do
    it "prevents small subgroup attacks" do
      # The validation should catch public keys that would lead to weak shared secrets
      params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters
      
      # Try to create a public key with y = 1 (would lead to shared secret = 1)
      dangerous_public = Crypto::DH::DHPublicKey.new(BigInt.new(1), params)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_public_key(dangerous_public).should be_false
      
      # Try to create a public key with y = p-1 (would lead to weak shared secrets)
      dangerous_public2 = Crypto::DH::DHPublicKey.new(params.p - 1, params)
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_public_key(dangerous_public2).should be_false
    end
    
    it "ensures private keys are in correct range for safe primes" do
      params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters
      q = (params.p - 1) // 2
      
      # Private key should be in range [2, q-1]
      valid_private = Crypto::DH::DHPrivateKey.new(q // 2, params)  # Middle of range
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(valid_private).should be_true
      
      # Edge cases should fail
      edge_private1 = Crypto::DH::DHPrivateKey.new(BigInt.new(1), params)  # Too small
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(edge_private1).should be_false
      
      edge_private2 = Crypto::DH::DHPrivateKey.new(q, params)  # Too large
      Crypto::Protocols::MTProto::DHUtils.validate_mtproto_private_key(edge_private2).should be_false
    end
  end
end