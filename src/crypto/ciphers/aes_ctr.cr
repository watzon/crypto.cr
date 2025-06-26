require "../base/cipher"
require "./aes"

module Crypto::Ciphers
  # AES in Counter (CTR) mode
  # CTR mode turns AES into a stream cipher by encrypting counter values
  # and XORing the result with the plaintext
  class AES_CTR < Crypto::StreamCipher
    private getter aes : AES
    private getter counter : Bytes
    private getter keystream : Bytes
    private getter keystream_pos : Int32

    # Initialize AES-CTR with a key and nonce/IV
    # @param key The encryption key (16, 24, or 32 bytes)
    # @param nonce The nonce/IV (typically 8-12 bytes, will be padded to 16 bytes)
    # @param initial_counter The initial counter value (default: 0)
    def initialize(key : Bytes, nonce : Bytes, initial_counter : UInt64 = 0)
      @aes = AES.new(key)
      
      # Initialize counter block (16 bytes)
      # Common practice: nonce in first 8-12 bytes, counter in last 4-8 bytes
      @counter = Bytes.new(16, 0)
      
      # Copy nonce to counter block
      nonce_size = Math.min(nonce.size, 12)  # Typically use up to 12 bytes for nonce
      nonce[0, nonce_size].copy_to(@counter)
      
      # Set initial counter value in the remaining bytes
      set_counter_value(initial_counter)
      
      # Initialize keystream buffer
      @keystream = Bytes.new(16)
      @keystream_pos = 16  # Force generation on first use
    end

    # Initialize with a full 16-byte counter block (for compatibility with test vectors)
    def self.new_with_counter_block(key : Bytes, counter_block : Bytes)
      raise ArgumentError.new("Counter block must be 16 bytes") unless counter_block.size == 16
      
      instance = allocate
      instance.initialize_with_counter_block(key, counter_block)
      instance
    end

    protected def initialize_with_counter_block(key : Bytes, counter_block : Bytes)
      @aes = AES.new(key)
      @counter = Bytes.new(16)
      counter_block.copy_to(@counter)
      @keystream = Bytes.new(16)
      @keystream_pos = 16
    end


    def encrypt(data : Bytes) : Bytes
      result = Bytes.new(data.size)
      
      data.each_with_index do |byte, i|
        # Generate new keystream block if needed
        if @keystream_pos >= 16
          generate_keystream
          @keystream_pos = 0
        end
        
        # XOR with keystream
        result[i] = byte ^ @keystream[@keystream_pos]
        @keystream_pos += 1
      end
      
      result
    end

    # In CTR mode, decryption is the same as encryption
    def decrypt(data : Bytes) : Bytes
      encrypt(data)
    end

    def key_size : Int32
      @aes.key_size
    end

    # Reset the cipher to a specific counter value
    def reset(counter_value : UInt64 = 0)
      set_counter_value(counter_value)
      @keystream_pos = 16  # Force regeneration
    end

    # Seek to a specific position in the stream
    # This allows random access encryption/decryption
    def seek(position : UInt64)
      # Calculate which block we're in
      block_number = position // 16
      block_offset = (position % 16).to_i32
      
      # Set counter to the correct block
      set_counter_value(block_number)
      
      # Generate keystream for this block
      generate_keystream
      @keystream_pos = block_offset
    end

    private def generate_keystream
      # Encrypt the counter to generate keystream
      @aes.encrypt(@counter).copy_to(@keystream)
      
      # Increment counter for next block
      increment_counter
    end

    private def increment_counter
      # Increment counter as a big-endian integer
      # Start from the last byte and carry over
      15.downto(8) do |i|
        if @counter[i] == 255
          @counter[i] = 0
          # Continue to next byte for carry
        else
          @counter[i] += 1
          break  # No carry needed
        end
      end
    end

    private def set_counter_value(value : UInt64)
      # Set the counter value in the last 8 bytes (big-endian)
      8.times do |i|
        @counter[15 - i] = ((value >> (i * 8)) & 0xFF).to_u8
      end
    end
  end
end