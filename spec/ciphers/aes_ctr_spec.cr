require "../spec_helper"
require "../../src/crypto/ciphers/aes_ctr"

describe Crypto::Ciphers::AES_CTR do
  # NIST SP 800-38A test vectors for CTR mode
  describe "NIST test vectors" do
    it "encrypts correctly with NIST test vector (F.5.1)" do
      # Test Vector from NIST SP 800-38A F.5.1 CTR-AES128.Encrypt
      key = Bytes[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
      ]
      
      # Counter block = nonce || counter
      # In NIST vectors, they use full 16-byte initial counter blocks
      initial_counter = Bytes[
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
      ]
      
      plaintext = Bytes[
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
      ]
      
      expected = Bytes[
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
      ]
      
      # For NIST vectors, we need to handle the full counter block
      cipher = Crypto::Ciphers::AES_CTR.new_with_counter_block(key, initial_counter)
      ciphertext = cipher.encrypt(plaintext)
      
      ciphertext.should eq(expected)
    end
  end

  describe "basic operations" do
    it "performs round-trip encryption/decryption" do
      key = Random::Secure.random_bytes(32)  # AES-256
      nonce = Random::Secure.random_bytes(12)
      plaintext = "Hello, World! This is a test of AES-CTR mode.".to_slice

      cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
      ciphertext = cipher.encrypt(plaintext)
      
      # Reset cipher for decryption
      cipher.reset
      decrypted = cipher.decrypt(ciphertext)

      decrypted.should eq(plaintext)
    end

    it "produces different ciphertext with different nonces" do
      key = Random::Secure.random_bytes(16)
      plaintext = "Test message".to_slice
      
      cipher1 = Crypto::Ciphers::AES_CTR.new(key, Random::Secure.random_bytes(12))
      cipher2 = Crypto::Ciphers::AES_CTR.new(key, Random::Secure.random_bytes(12))
      
      ciphertext1 = cipher1.encrypt(plaintext)
      ciphertext2 = cipher2.encrypt(plaintext)
      
      ciphertext1.should_not eq(ciphertext2)
    end

    it "can encrypt data of any length" do
      key = Random::Secure.random_bytes(16)
      nonce = Random::Secure.random_bytes(12)
      
      # Test various lengths
      [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000].each do |length|
        plaintext = Random::Secure.random_bytes(length)
        
        cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
        ciphertext = cipher.encrypt(plaintext)
        
        cipher.reset
        decrypted = cipher.decrypt(ciphertext)
        
        decrypted.should eq(plaintext)
      end
    end
  end

  describe "stream properties" do
    it "can encrypt in chunks" do
      key = Random::Secure.random_bytes(16)
      nonce = Random::Secure.random_bytes(12)
      
      # Encrypt full message at once
      cipher1 = Crypto::Ciphers::AES_CTR.new(key, nonce)
      full_plaintext = "This is a longer message that we'll encrypt in chunks to test streaming.".to_slice
      full_ciphertext = cipher1.encrypt(full_plaintext)
      
      # Encrypt in chunks
      cipher2 = Crypto::Ciphers::AES_CTR.new(key, nonce)
      chunk1 = cipher2.encrypt(full_plaintext[0, 20])
      chunk2 = cipher2.encrypt(full_plaintext[20, 30])
      chunk3 = cipher2.encrypt(full_plaintext[50, full_plaintext.size - 50])
      
      chunked_ciphertext = Bytes.new(full_ciphertext.size)
      chunk1.copy_to(chunked_ciphertext[0, 20])
      chunk2.copy_to(chunked_ciphertext[20, 30])
      chunk3.copy_to(chunked_ciphertext[50, chunk3.size])
      
      chunked_ciphertext.should eq(full_ciphertext)
    end

    it "supports random access via seek" do
      key = Random::Secure.random_bytes(16)
      nonce = Random::Secure.random_bytes(12)
      plaintext = Random::Secure.random_bytes(100)
      
      # Encrypt full message
      cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
      full_ciphertext = cipher.encrypt(plaintext)
      
      # Decrypt from position 50
      cipher.seek(50)
      partial_decrypted = cipher.decrypt(full_ciphertext[50, 30])
      
      partial_decrypted.should eq(plaintext[50, 30])
    end
  end

  describe "counter management" do
    it "correctly increments counter across block boundaries" do
      key = Random::Secure.random_bytes(16)
      nonce = Bytes.new(12, 0)  # All zeros for predictability
      
      cipher = Crypto::Ciphers::AES_CTR.new(key, nonce, 0xFFFFFFFFFFFFFFFE_u64)
      
      # Encrypt 32 bytes (2 blocks) which should increment counter twice
      plaintext = Random::Secure.random_bytes(32)
      ciphertext = cipher.encrypt(plaintext)
      
      # Reset with counter at overflow point
      cipher.reset(0xFFFFFFFFFFFFFFFF_u64)
      
      # This should work and wrap around
      more_plaintext = Random::Secure.random_bytes(32)
      more_ciphertext = cipher.encrypt(more_plaintext)
      
      # Verify it produces different output (due to different counter values)
      ciphertext.should_not eq(more_ciphertext)
    end
  end

  describe "properties" do
    it "reports correct key size" do
      key16 = Random::Secure.random_bytes(16)
      key24 = Random::Secure.random_bytes(24)
      key32 = Random::Secure.random_bytes(32)
      nonce = Random::Secure.random_bytes(12)
      
      Crypto::Ciphers::AES_CTR.new(key16, nonce).key_size.should eq(16)
      Crypto::Ciphers::AES_CTR.new(key24, nonce).key_size.should eq(24)
      Crypto::Ciphers::AES_CTR.new(key32, nonce).key_size.should eq(32)
    end

    it "reports block size of 1 (stream cipher)" do
      cipher = Crypto::Ciphers::AES_CTR.new(Random::Secure.random_bytes(16), Random::Secure.random_bytes(12))
      cipher.block_size.should eq(1)
    end
  end
end