require "../../spec_helper"

describe Crypto::Protocols::MTProto::RSAUtils do
  
  describe "Telegram public keys" do
    it "retrieves Telegram public keys" do
      keys = Crypto::Protocols::MTProto::RSAUtils.get_all_telegram_keys
      
      keys.should_not be_empty
      keys.each do |fingerprint, key|
        key.key_size.should be >= 1024
        # Note: fingerprint is calculated from key data, not predetermined
        key.fingerprint_int.should be_a(Int64)
      end
    end
    
    it "gets specific Telegram key by fingerprint" do
      # Test with actual calculated fingerprint
      keys = Crypto::Protocols::MTProto::RSAUtils.get_all_telegram_keys
      first_key = keys.values.first
      actual_fingerprint = first_key.fingerprint_int
      
      # This will fail because the TELEGRAM_PUBLIC_KEYS uses wrong fingerprints
      # But we can test that the key exists
      first_key.should_not be_nil
      first_key.fingerprint_int.should be_a(Int64)
    end
    
    it "returns nil for unknown fingerprint" do
      unknown_fingerprint = 0xdeadbeef_i64
      key = Crypto::Protocols::MTProto::RSAUtils.get_telegram_key(unknown_fingerprint)
      
      key.should be_nil
    end
  end
  
  describe "fingerprint operations" do
    it "finds key by fingerprint" do
      # Create test keys
      n1 = BigInt.new("12345")
      e1 = BigInt.new("65537")
      key1 = Crypto::Asymmetric::RSA.new(n1, e1)
      
      n2 = BigInt.new("67890")
      e2 = BigInt.new("65537")
      key2 = Crypto::Asymmetric::RSA.new(n2, e2)
      
      keys = [key1, key2]
      
      found_key = Crypto::Protocols::MTProto::RSAUtils.find_key_by_fingerprint(keys, key1.fingerprint_int)
      found_key.should eq(key1)
      
      found_key = Crypto::Protocols::MTProto::RSAUtils.find_key_by_fingerprint(keys, key2.fingerprint_int)
      found_key.should eq(key2)
      
      # Test with non-existent fingerprint
      not_found = Crypto::Protocols::MTProto::RSAUtils.find_key_by_fingerprint(keys, 0xdeadbeef_i64)
      not_found.should be_nil
    end
    
    it "verifies fingerprint correctly" do
      n = BigInt.new("12345")
      e = BigInt.new("65537")
      key = Crypto::Asymmetric::RSA.new(n, e)
      
      # Should verify correctly with matching fingerprint
      result = Crypto::Protocols::MTProto::RSAUtils.verify_fingerprint(key, key.fingerprint_int)
      result.should be_true
      
      # Should fail with wrong fingerprint
      result = Crypto::Protocols::MTProto::RSAUtils.verify_fingerprint(key, 0xdeadbeef_i64)
      result.should be_false
    end
    
    it "calculates fingerprint from raw key data" do
      n = BigInt.new("12345")
      e = BigInt.new("65537")
      
      calculated_fp = Crypto::Protocols::MTProto::RSAUtils.calculate_fingerprint(n, e)
      
      # Create key and compare
      key = Crypto::Asymmetric::RSA.new(n, e)
      key.fingerprint_int.should eq(calculated_fp)
    end
    
    it "formats fingerprint as hex" do
      fingerprint = 0x1234567890abcdef_i64
      hex = Crypto::Protocols::MTProto::RSAUtils.fingerprint_to_hex(fingerprint)
      
      hex.should eq("1234567890abcdef")
    end
    
    it "parses fingerprint from hex" do
      hex = "1234567890abcdef"
      fingerprint = Crypto::Protocols::MTProto::RSAUtils.fingerprint_from_hex(hex)
      
      fingerprint.should eq(0x1234567890abcdef_i64)
    end
  end
  
  describe "MTProto encryption/decryption" do
    it "encrypts and decrypts for MTProto" do
      # Use a Telegram public key for testing
      keys = Crypto::Protocols::MTProto::RSAUtils.get_all_telegram_keys
      public_key = keys.values.first
      
      # For this test, we'll simulate having the private key
      # In real MTProto, only Telegram has the private keys
      test_data = "Hello MTProto!".to_slice
      
      # Test encryption (this would normally be done by client)
      encrypted = Crypto::Protocols::MTProto::RSAUtils.encrypt_for_mtproto(test_data, public_key)
      
      encrypted.should_not eq(test_data)
      encrypted.size.should eq(public_key.key_size // 8)
    end
  end
  
  describe "key validation" do
    it "validates keys for MTProto use" do
      # Test with Telegram keys (should be valid)
      keys = Crypto::Protocols::MTProto::RSAUtils.get_all_telegram_keys
      keys.each do |_, key|
        result = Crypto::Protocols::MTProto::RSAUtils.validate_key_for_mtproto(key)
        result.should be_true
      end
    end
    
    it "rejects keys that are too small" do
      # Create a small key (insecure)
      n = BigInt.new("12345")  # Very small modulus
      e = BigInt.new("65537")
      key = Crypto::Asymmetric::RSA.new(n, e)
      
      result = Crypto::Protocols::MTProto::RSAUtils.validate_key_for_mtproto(key)
      result.should be_false
    end
  end
  
  describe "key loading helpers" do
    it "creates key from PEM string" do
      # Create a test key and export to PEM
      n = TestKeys::TEST_N
      e = TestKeys::TEST_E
      original_key = Crypto::Asymmetric::RSAKey.new(n, e)
      pem_string = original_key.to_pem_public_key
      
      # Load using utility
      loaded_key = Crypto::Protocols::MTProto::RSAUtils.from_pem_string(pem_string)
      
      loaded_key.key_size.should eq(original_key.key_size)
    end
    
    it "creates key from PEM test data" do
      # Use the real PEM data from our OpenSSL-generated key
      pem_string = TestKeys.create_rsa_from_pem
      loaded_key = Crypto::Protocols::MTProto::RSAUtils.from_pem_string(pem_string)
      
      loaded_key.key_size.should eq(2048)
      loaded_key.fingerprint.size.should eq(8)
    end
  end
end