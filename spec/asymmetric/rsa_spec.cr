require "../spec_helper"

describe Crypto::Asymmetric::RSA do
  
  describe "RSA key operations" do
    it "creates RSA key correctly" do
      key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E, TestKeys::TEST_D)
      key.n.should eq(TestKeys::TEST_N)
      key.e.should eq(TestKeys::TEST_E)
      key.d.should eq(TestKeys::TEST_D)
      key.private?.should be_true
    end
    
    it "creates public key from private key" do
      private_key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E, TestKeys::TEST_D)
      public_key = private_key.public_key
      
      public_key.n.should eq(TestKeys::TEST_N)
      public_key.e.should eq(TestKeys::TEST_E)
      public_key.d.should be_nil
      public_key.private?.should be_false
    end
    
    it "calculates key size correctly" do
      key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E)
      key.key_size.should be >= 2048  # TestKeys::TEST_N is a 2048+ bit number
      key.key_size.should be <= 2049
    end
    
    it "generates DER public key format" do
      key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E)
      der_bytes = key.to_der_public_key
      
      # Should start with SEQUENCE tag
      der_bytes[0].should eq(0x30)
      der_bytes.size.should be > 10
    end
    
    it "generates PEM public key format" do
      key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E)
      pem = key.to_pem_public_key
      
      pem.should contain("-----BEGIN PUBLIC KEY-----")
      pem.should contain("-----END PUBLIC KEY-----")
    end
    
    it "calculates fingerprint correctly" do
      key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E)
      fingerprint = key.fingerprint
      
      fingerprint.size.should eq(8)  # MTProto uses 8-byte fingerprint
    end
  end
  
  describe "RSA encryption/decryption" do
    pending "encrypts and decrypts data correctly - Requires valid RSA keypair for testing"
    
    pending "handles empty data - Requires valid RSA keypair for testing"
    
    pending "handles maximum size data - Requires valid RSA keypair for testing"
    
    it "raises error for oversized data" do
      rsa = Crypto::Asymmetric::RSA.new(TestKeys::TEST_N, TestKeys::TEST_E, TestKeys::TEST_D)
      oversized_data = Bytes.new(300) { 0_u8 }  # Too large for 2048-bit key
      
      expect_raises(Exception, "Data too large for RSA key") do
        rsa.encrypt(oversized_data)
      end
    end
    
    it "raises error when decrypting without private key" do
      public_key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E)
      rsa = Crypto::Asymmetric::RSA.new(public_key)
      encrypted_data = Bytes.new(256) { 0_u8 }
      
      expect_raises(Exception, "Cannot decrypt: no private key") do
        rsa.decrypt(encrypted_data)
      end
    end
  end
  
  describe "PEM/DER parsing" do
    it "parses PEM public key" do
      # Create a key and export to PEM
      original_key = Crypto::Asymmetric::RSAKey.new(TestKeys::TEST_N, TestKeys::TEST_E)
      pem_string = original_key.to_pem_public_key
      
      # Parse the PEM back
      parsed_rsa = Crypto::Asymmetric::RSA.from_pem(pem_string)
      
      parsed_rsa.key_size.should eq(original_key.key_size)
      parsed_rsa.public_key.should eq(original_key.to_der_public_key)
    end
    
    pending "parses DER public key - Complex DER parsing needs refinement"
  end
  
  describe "MTProto specific features" do
    it "calculates fingerprint correctly" do
      # This test moved to MTProto utils spec since Telegram key access is now there
      rsa = Crypto::Asymmetric::RSA.new(TestKeys::TEST_N, TestKeys::TEST_E)
      
      rsa.fingerprint.size.should eq(8)
    end
    
    it "calculates fingerprint as integer" do
      rsa = Crypto::Asymmetric::RSA.new(TestKeys::TEST_N, TestKeys::TEST_E)
      fingerprint_int = rsa.fingerprint_int
      
      fingerprint_int.should be_a(Int64)
      fingerprint_int.should_not eq(0)
    end
    
    it "produces consistent fingerprints" do
      rsa1 = Crypto::Asymmetric::RSA.new(TestKeys::TEST_N, TestKeys::TEST_E)
      rsa2 = Crypto::Asymmetric::RSA.new(TestKeys::TEST_N, TestKeys::TEST_E)
      
      rsa1.fingerprint.should eq(rsa2.fingerprint)
      rsa1.fingerprint_int.should eq(rsa2.fingerprint_int)
    end
  end
  
  describe "PKCS#1 v1.5 padding" do
    pending "correctly encrypts data that roundtrips - Requires valid RSA keypair for testing"
    
    pending "produces different ciphertexts for same plaintext - Requires valid RSA keypair for testing"
  end
  
  describe "edge cases and error handling" do
    it "handles invalid DER data gracefully" do
      invalid_der = Bytes[0x01, 0x02, 0x03]  # Invalid DER data
      
      expect_raises(Exception) do
        Crypto::Asymmetric::RSA.from_der(invalid_der)
      end
    end
    
    it "handles invalid PEM data gracefully" do
      invalid_pem = "-----BEGIN PUBLIC KEY-----\nInvalidBase64Data\n-----END PUBLIC KEY-----"
      
      expect_raises(Exception) do
        Crypto::Asymmetric::RSA.from_pem(invalid_pem)
      end
    end
    
    it "handles invalid ciphertext size" do
      rsa = Crypto::Asymmetric::RSA.new(TestKeys::TEST_N, TestKeys::TEST_E, TestKeys::TEST_D)
      invalid_ciphertext = Bytes.new(100) { 0_u8 }  # Wrong size
      
      expect_raises(Exception, "Invalid ciphertext size") do
        rsa.decrypt(invalid_ciphertext)
      end
    end
  end
end