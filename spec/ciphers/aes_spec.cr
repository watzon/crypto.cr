require "../spec_helper"
require "../../src/crypto/ciphers/aes"

describe Crypto::Ciphers::AES do
  # NIST test vectors from FIPS 197
  # Appendix B - Cipher Example
  describe "AES-128" do
    it "encrypts correctly with NIST test vector" do
      # NIST FIPS 197 Appendix B example
      key = Bytes[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
      ]
      
      plaintext = Bytes[
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
      ]
      
      expected_ciphertext = Bytes[
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
      ]

      aes = Crypto::Ciphers::AES.new(key)
      ciphertext = aes.encrypt(plaintext)
      
      ciphertext.should eq(expected_ciphertext)
    end
    
    it "decrypts correctly with NIST test vector" do
      key = Bytes[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
      ]
      
      ciphertext = Bytes[
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
      ]
      
      expected_plaintext = Bytes[
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
      ]

      aes = Crypto::Ciphers::AES.new(key)
      plaintext = aes.decrypt(ciphertext)
      
      plaintext.should eq(expected_plaintext)
    end

    it "performs round-trip encryption/decryption" do
      key = Random::Secure.random_bytes(16)
      plaintext = Random::Secure.random_bytes(16)

      aes = Crypto::Ciphers::AES.new(key)
      ciphertext = aes.encrypt(plaintext)
      decrypted = aes.decrypt(ciphertext)

      decrypted.should eq(plaintext)
    end
  end

  # NIST test vectors from FIPS 197
  # Appendix C.2 - AES-192
  describe "AES-192" do
    it "encrypts correctly with NIST test vector" do
      key = Bytes[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
      ]
      
      plaintext = Bytes[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
      ]
      
      expected_ciphertext = Bytes[
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
      ]

      aes = Crypto::Ciphers::AES.new(key)
      ciphertext = aes.encrypt(plaintext)
      
      ciphertext.should eq(expected_ciphertext)
    end
    
    it "decrypts correctly with NIST test vector" do
      key = Bytes[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
      ]
      
      ciphertext = Bytes[
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
      ]
      
      expected_plaintext = Bytes[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
      ]

      aes = Crypto::Ciphers::AES.new(key)
      plaintext = aes.decrypt(ciphertext)
      
      plaintext.should eq(expected_plaintext)
    end

    it "performs round-trip encryption/decryption" do
      key = Random::Secure.random_bytes(24)
      plaintext = Random::Secure.random_bytes(16)

      aes = Crypto::Ciphers::AES.new(key)
      ciphertext = aes.encrypt(plaintext)
      decrypted = aes.decrypt(ciphertext)

      decrypted.should eq(plaintext)
    end
  end

  # NIST test vectors from FIPS 197
  # Appendix C.3 - AES-256
  describe "AES-256" do
    it "encrypts correctly with NIST test vector" do
      key = Bytes[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
      ]
      
      plaintext = Bytes[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
      ]
      
      expected_ciphertext = Bytes[
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
      ]

      aes = Crypto::Ciphers::AES.new(key)
      ciphertext = aes.encrypt(plaintext)
      
      ciphertext.should eq(expected_ciphertext)
    end
    
    it "decrypts correctly with NIST test vector" do
      key = Bytes[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
      ]
      
      ciphertext = Bytes[
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
      ]
      
      expected_plaintext = Bytes[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
      ]

      aes = Crypto::Ciphers::AES.new(key)
      plaintext = aes.decrypt(ciphertext)
      
      plaintext.should eq(expected_plaintext)
    end

    it "performs round-trip encryption/decryption" do
      key = Random::Secure.random_bytes(32)
      plaintext = Random::Secure.random_bytes(16)

      aes = Crypto::Ciphers::AES.new(key)
      ciphertext = aes.encrypt(plaintext)
      decrypted = aes.decrypt(ciphertext)

      decrypted.should eq(plaintext)
    end
  end

  describe "error handling" do
    it "raises error for invalid key size" do
      expect_raises(ArgumentError, /Invalid AES key size/) do
        Crypto::Ciphers::AES.new(Bytes.new(15))  # Invalid size
      end
    end

    it "raises error for invalid block size on encryption" do
      aes = Crypto::Ciphers::AES.new(Random::Secure.random_bytes(16))
      
      expect_raises(ArgumentError, /AES operates on 16-byte blocks/) do
        aes.encrypt(Bytes.new(15))  # Invalid block size
      end
    end

    it "raises error for invalid block size on decryption" do
      aes = Crypto::Ciphers::AES.new(Random::Secure.random_bytes(16))
      
      expect_raises(ArgumentError, /AES operates on 16-byte blocks/) do
        aes.decrypt(Bytes.new(17))  # Invalid block size
      end
    end
  end

  describe "properties" do
    it "reports correct block size" do
      aes = Crypto::Ciphers::AES.new(Random::Secure.random_bytes(16))
      aes.block_size.should eq(16)
    end

    it "reports correct key size for AES-128" do
      aes = Crypto::Ciphers::AES.new(Random::Secure.random_bytes(16))
      aes.key_size.should eq(16)
    end

    it "reports correct key size for AES-192" do
      aes = Crypto::Ciphers::AES.new(Random::Secure.random_bytes(24))
      aes.key_size.should eq(24)
    end

    it "reports correct key size for AES-256" do
      aes = Crypto::Ciphers::AES.new(Random::Secure.random_bytes(32))
      aes.key_size.should eq(32)
    end
  end
end