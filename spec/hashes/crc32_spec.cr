require "../spec_helper"
require "../../src/crypto/hashes/crc32"

describe Crypto::Hashes::CRC32 do
  crc32 = Crypto::Hashes::CRC32.new
  
  describe "#hash" do
    it "calculates CRC32 for empty string" do
      crc32.hash("").should eq("00000000")
    end
    
    it "calculates CRC32 for single byte" do
      crc32.hash("a").should eq("E8B7BE43")
    end
    
    it "calculates CRC32 for 'hello'" do
      crc32.hash("hello").should eq("3610A686")
    end
    
    it "calculates CRC32 for 'Hello, World!'" do
      crc32.hash("Hello, World!").should eq("EC4AC3D0")
    end
    
    it "calculates CRC32 for '123456789'" do
      # This is the standard CRC32 test vector
      crc32.hash("123456789").should eq("CBF43926")
    end
    
    it "calculates CRC32 for longer text" do
      text = "The quick brown fox jumps over the lazy dog"
      crc32.hash(text).should eq("414FA339")
    end
  end
  
  describe "#checksum" do
    it "returns UInt32 checksum for '123456789'" do
      crc32.checksum("123456789").should eq(0xCBF43926_u32)
    end
    
    it "returns UInt32 checksum for empty string" do
      crc32.checksum("").should eq(0x00000000_u32)
    end
    
    it "returns UInt32 checksum for 'hello'" do
      crc32.checksum("hello").should eq(0x3610A686_u32)
    end
  end
  
  describe "#hash_bytes" do
    it "returns 4 bytes for CRC32" do
      result = crc32.hash_bytes("123456789")
      result.size.should eq(4)
      result.should eq(Bytes[0xCB, 0xF4, 0x39, 0x26])
    end
    
    it "returns correct bytes for empty string" do
      result = crc32.hash_bytes("")
      result.should eq(Bytes[0x00, 0x00, 0x00, 0x00])
    end
    
    it "returns correct bytes for 'hello'" do
      result = crc32.hash_bytes("hello")
      result.should eq(Bytes[0x36, 0x10, 0xA6, 0x86])
    end
  end
  
  describe "class methods" do
    it "calculates checksum using class method" do
      Crypto::Hashes::CRC32.checksum("123456789".to_slice).should eq(0xCBF43926_u32)
    end
    
    it "handles binary data correctly" do
      # Test with binary data that contains null bytes
      binary_data = Bytes[0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD]
      checksum = Crypto::Hashes::CRC32.checksum(binary_data)
      checksum.should be_a(UInt32)
    end
  end
  
  describe "MTProto compatibility" do
    it "calculates CRC32 for MTProto test data" do
      # Test vector verified with our IEEE 802.3 CRC32 implementation
      # This is compatible with MTProto which uses standard CRC32
      test_data = "telegram"
      expected = 0x043320DA_u32  # CRC32 for "telegram" using IEEE 802.3 polynomial
      crc32.checksum(test_data).should eq(expected)
    end
    
    it "handles MTProto message structure" do
      # Simulate a simple MTProto message structure
      message = Bytes[0x78, 0x97, 0x46, 0x60, 0x3E, 0x05, 0x49, 0x82]
      checksum = Crypto::Hashes::CRC32.checksum(message)
      checksum.should be_a(UInt32)
    end
  end
  
  describe "properties" do
    it "has correct output size" do
      crc32.output_size.should eq(4)
    end
    
    it "has correct block size" do
      crc32.block_size.should eq(1)
    end
  end
  
  describe "edge cases" do
    it "handles very long strings" do
      long_string = "a" * 10000
      result = crc32.hash(long_string)
      result.size.should eq(8)  # 8 hex characters
    end
    
    it "handles unicode strings" do
      unicode_string = "Hello, 世界! 🌍"
      result = crc32.hash(unicode_string)
      result.size.should eq(8)
    end
    
    it "produces consistent results" do
      input = "consistency test"
      result1 = crc32.hash(input)
      result2 = crc32.hash(input)
      result1.should eq(result2)
    end
  end
end