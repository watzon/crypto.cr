require "../base/hash_algorithm"

module Crypto::Hashes
  class Sha1 < Crypto::HashAlgorithm
    # SHA-1 constants
    private K = [
      0x5a827999_u32, 0x6ed9eba1_u32, 0x8f1bbcdc_u32, 0xca62c1d6_u32
    ]
    
    # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 5 primes)
    private H0 = [
      0x67452301_u32, 0xefcdab89_u32, 0x98badcfe_u32, 0x10325476_u32, 0xc3d2e1f0_u32
    ]
    
    def hash(input : String) : String
      hash_bytes(input.to_slice).hexstring
    end
    
    def hash_bytes(input : Bytes) : Bytes
      # Initialize hash values
      h = H0.dup
      
      # Pre-processing: adding padding bits
      message = preprocess(input)
      
      # Process the message in successive 512-bit chunks
      (0...message.size).step(64) do |chunk_start|
        chunk = message[chunk_start, 64]
        process_chunk(chunk, h)
      end
      
      # Produce the final hash value as a 160-bit number (20 bytes)
      result = Bytes.new(20)
      h.each_with_index do |word, i|
        result[i * 4] = ((word >> 24) & 0xff).to_u8
        result[i * 4 + 1] = ((word >> 16) & 0xff).to_u8
        result[i * 4 + 2] = ((word >> 8) & 0xff).to_u8
        result[i * 4 + 3] = (word & 0xff).to_u8
      end
      
      result
    end
    
    def output_size : Int32
      # SHA-1 output size
      20
    end
    
    def block_size : Int32
      # SHA-1 block size
      64
    end
    
    private def preprocess(input : Bytes) : Bytes
      # Pre-processing: adding padding bits
      message_len = input.size
      
      # append the '1' bit (0x80)
      message = input + Bytes[0x80]
      
      # append 0 <= k < 512 bits '0', such that the resulting message length in bits
      # is congruent to 448 (mod 512)
      while (message.size % 64) != 56
        message += Bytes[0x00]
      end
      
      # append original length in bits mod 2^64 to message as 64-bit big-endian integer
      bit_len = message_len.to_u64 * 8
      8.times do |i|
        message += Bytes[((bit_len >> (56 - i * 8)) & 0xff).to_u8]
      end
      
      message
    end
    
    private def process_chunk(chunk : Bytes, h : Array(UInt32))
      # Break chunk into sixteen 32-bit big-endian words
      w = Array(UInt32).new(80, 0_u32)
      
      16.times do |i|
        w[i] = (chunk[i * 4].to_u32 << 24) |
               (chunk[i * 4 + 1].to_u32 << 16) |
               (chunk[i * 4 + 2].to_u32 << 8) |
               chunk[i * 4 + 3].to_u32
      end
      
      # Extend the sixteen 32-bit words into eighty 32-bit words
      (16..79).each do |i|
        w[i] = rotleft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
      end
      
      # Initialize hash value for this chunk
      a, b, c, d, e = h[0], h[1], h[2], h[3], h[4]
      
      # Main loop
      80.times do |i|
        case i
        when 0..19
          f = (b & c) | ((~b) & d)
          k = K[0]
        when 20..39
          f = b ^ c ^ d
          k = K[1]
        when 40..59
          f = (b & c) | (b & d) | (c & d)
          k = K[2]
        when 60..79
          f = b ^ c ^ d
          k = K[3]
        else
          raise "Invalid index"
        end
        
        temp = (rotleft(a, 5) &+ f &+ e &+ k &+ w[i]) & 0xffffffff_u32
        e = d
        d = c
        c = rotleft(b, 30)
        b = a
        a = temp
      end
      
      # Add this chunk's hash to result so far
      h[0] = (h[0] &+ a) & 0xffffffff_u32
      h[1] = (h[1] &+ b) & 0xffffffff_u32
      h[2] = (h[2] &+ c) & 0xffffffff_u32
      h[3] = (h[3] &+ d) & 0xffffffff_u32
      h[4] = (h[4] &+ e) & 0xffffffff_u32
    end
    
    private def rotleft(value : UInt32, amount : Int32) : UInt32
      ((value << amount) | (value >> (32 - amount))) & 0xffffffff_u32
    end
  end
end