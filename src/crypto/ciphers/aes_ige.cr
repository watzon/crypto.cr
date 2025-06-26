require "../base/cipher"
require "./aes"

module Crypto::Ciphers
  # AES in Infinite Garble Extension (IGE) mode
  # IGE mode is primarily used by Telegram's MTProto protocol
  # 
  # Formula for encryption: c_i = AES_K(m_i ⊕ c_{i-1}) ⊕ m_{i-1}
  # Formula for decryption: m_i = AES_K^{-1}(c_i ⊕ m_{i-1}) ⊕ c_{i-1}
  #
  # This mode propagates errors forward - if one block is corrupted,
  # all subsequent blocks will fail to decrypt correctly
  class AES_IGE < Crypto::BlockCipherMode
    private getter aes : AES
    private getter iv : Bytes
    
    # Initialize AES-IGE with a key and initialization vector
    # @param key The encryption key (16, 24, or 32 bytes)
    # @param iv The initialization vector (must be 32 bytes)
    #           First 16 bytes: c_0 (initial ciphertext block)
    #           Last 16 bytes: m_0 (initial plaintext block)
    #           This follows OpenSSL's convention
    def initialize(key : Bytes, @iv : Bytes)
      @aes = AES.new(key)
      
      unless @iv.size == 32
        raise ArgumentError.new("IGE mode requires a 32-byte IV (16 bytes for m_0 and 16 bytes for c_0)")
      end
    end

    def encrypt(data : Bytes) : Bytes
      unless data.size % 16 == 0
        raise ArgumentError.new("IGE mode requires data length to be a multiple of 16 bytes")
      end
      
      result = Bytes.new(data.size)
      
      # Extract initial values from IV (OpenSSL convention)
      # First 16 bytes are the initial ciphertext block (c_0) 
      # Last 16 bytes are the initial plaintext block (m_0)
      c_prev = Bytes.new(16)
      m_prev = Bytes.new(16)
      @iv[0, 16].copy_to(c_prev)
      @iv[16, 16].copy_to(m_prev)
      
      # Process each block
      blocks = data.size // 16
      blocks.times do |i|
        block_offset = i * 16
        
        # Extract current plaintext block
        m_i = data[block_offset, 16]
        
        # c_i = AES_K(m_i ⊕ c_{i-1}) ⊕ m_{i-1}
        temp = Bytes.new(16)
        16.times do |j|
          temp[j] = m_i[j] ^ c_prev[j]
        end
        
        c_i = @aes.encrypt(temp)
        16.times do |j|
          c_i[j] ^= m_prev[j]
        end
        
        # Copy to result
        c_i.copy_to(result[block_offset, 16])
        
        # Update previous blocks for next iteration
        m_i.copy_to(m_prev)
        c_i.copy_to(c_prev)
      end
      
      result
    end

    def decrypt(data : Bytes) : Bytes
      unless data.size % 16 == 0
        raise ArgumentError.new("IGE mode requires data length to be a multiple of 16 bytes")
      end
      
      result = Bytes.new(data.size)
      
      # Extract initial values from IV (OpenSSL convention)
      # First 16 bytes are the initial ciphertext block (c_0) 
      # Last 16 bytes are the initial plaintext block (m_0)
      c_prev = Bytes.new(16)
      m_prev = Bytes.new(16)
      @iv[0, 16].copy_to(c_prev)
      @iv[16, 16].copy_to(m_prev)
      
      # Process each block
      blocks = data.size // 16
      blocks.times do |i|
        block_offset = i * 16
        
        # Extract current ciphertext block
        c_i = data[block_offset, 16]
        
        # m_i = AES_K^{-1}(c_i ⊕ m_{i-1}) ⊕ c_{i-1}
        temp = Bytes.new(16)
        16.times do |j|
          temp[j] = c_i[j] ^ m_prev[j]
        end
        
        m_i = @aes.decrypt(temp)
        16.times do |j|
          m_i[j] ^= c_prev[j]
        end
        
        # Copy to result
        m_i.copy_to(result[block_offset, 16])
        
        # Update previous blocks for next iteration
        m_i.copy_to(m_prev)
        c_i.copy_to(c_prev)
      end
      
      result
    end

    def block_size : Int32
      16  # AES block size
    end

    def key_size : Int32
      @aes.key_size
    end
  end
end