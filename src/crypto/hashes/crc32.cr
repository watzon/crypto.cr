require "../base/hash_algorithm"

module Crypto::Hashes
  # CRC32 implementation with IEEE 802.3 polynomial (0xEDB88320)
  # This is the standard CRC32 used in ZIP files, PNG, and many other formats
  # Also compatible with MTProto protocol requirements
  class CRC32 < Crypto::HashAlgorithm
    # IEEE 802.3 polynomial in reversed bit order
    POLYNOMIAL = 0xEDB88320_u32
    
    # Pre-computed lookup table for faster CRC calculation
    @@table : Array(UInt32)? = nil
    
    # Initialize the CRC32 lookup table
    private def self.init_table
      table = Array(UInt32).new(256) do |i|
        crc = i.to_u32
        8.times do
          if (crc & 1) != 0
            crc = (crc >> 1) ^ POLYNOMIAL
          else
            crc >>= 1
          end
        end
        crc
      end
      @@table = table
    end
    
    # Get the lookup table, initializing if necessary
    private def self.table
      @@table || begin
        init_table
        @@table.not_nil!
      end
    end
    
    # Calculate CRC32 checksum for given bytes
    def self.checksum(data : Bytes) : UInt32
      crc = 0xFFFFFFFF_u32
      table = self.table
      
      data.each do |byte|
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
      end
      
      crc ^ 0xFFFFFFFF_u32
    end
    
    # Hash a string and return hex string
    def hash(input : String) : String
      checksum = self.class.checksum(input.to_slice)
      checksum.to_s(16, precision: 8, upcase: true)
    end
    
    # Hash bytes and return the CRC32 as 4 bytes (big-endian)
    def hash_bytes(input : Bytes) : Bytes
      checksum = self.class.checksum(input)
      bytes = Bytes.new(4)
      bytes[0] = ((checksum >> 24) & 0xFF).to_u8
      bytes[1] = ((checksum >> 16) & 0xFF).to_u8
      bytes[2] = ((checksum >> 8) & 0xFF).to_u8
      bytes[3] = (checksum & 0xFF).to_u8
      bytes
    end
    
    # CRC32 outputs 32 bits = 4 bytes
    def output_size : Int32
      4
    end
    
    # CRC32 doesn't have a fixed block size, but we'll use a reasonable default
    def block_size : Int32
      1
    end
    
    # Convenience method to get CRC32 as UInt32
    def checksum(input : String) : UInt32
      self.class.checksum(input.to_slice)
    end
    
    # Convenience method to get CRC32 as UInt32 from bytes
    def checksum(input : Bytes) : UInt32
      self.class.checksum(input)
    end
  end
end