require "../base/hash_algorithm"

module Crypto::Hashes
  class Sha256 < Crypto::HashAlgorithm
    # SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    private K = [
      0x428a2f98_u32, 0x71374491_u32, 0xb5c0fbcf_u32, 0xe9b5dba5_u32,
      0x3956c25b_u32, 0x59f111f1_u32, 0x923f82a4_u32, 0xab1c5ed5_u32,
      0xd807aa98_u32, 0x12835b01_u32, 0x243185be_u32, 0x550c7dc3_u32,
      0x72be5d74_u32, 0x80deb1fe_u32, 0x9bdc06a7_u32, 0xc19bf174_u32,
      0xe49b69c1_u32, 0xefbe4786_u32, 0x0fc19dc6_u32, 0x240ca1cc_u32,
      0x2de92c6f_u32, 0x4a7484aa_u32, 0x5cb0a9dc_u32, 0x76f988da_u32,
      0x983e5152_u32, 0xa831c66d_u32, 0xb00327c8_u32, 0xbf597fc7_u32,
      0xc6e00bf3_u32, 0xd5a79147_u32, 0x06ca6351_u32, 0x14292967_u32,
      0x27b70a85_u32, 0x2e1b2138_u32, 0x4d2c6dfc_u32, 0x53380d13_u32,
      0x650a7354_u32, 0x766a0abb_u32, 0x81c2c92e_u32, 0x92722c85_u32,
      0xa2bfe8a1_u32, 0xa81a664b_u32, 0xc24b8b70_u32, 0xc76c51a3_u32,
      0xd192e819_u32, 0xd6990624_u32, 0xf40e3585_u32, 0x106aa070_u32,
      0x19a4c116_u32, 0x1e376c08_u32, 0x2748774c_u32, 0x34b0bcb5_u32,
      0x391c0cb3_u32, 0x4ed8aa4a_u32, 0x5b9cca4f_u32, 0x682e6ff3_u32,
      0x748f82ee_u32, 0x78a5636f_u32, 0x84c87814_u32, 0x8cc70208_u32,
      0x90befffa_u32, 0xa4506ceb_u32, 0xbef9a3f7_u32, 0xc67178f2_u32
    ]
    
    # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    private H0 = [
      0x6a09e667_u32, 0xbb67ae85_u32, 0x3c6ef372_u32, 0xa54ff53a_u32,
      0x510e527f_u32, 0x9b05688c_u32, 0x1f83d9ab_u32, 0x5be0cd19_u32
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
      
      # Produce the final hash value as a 256-bit number (32 bytes)
      result = Bytes.new(32)
      h.each_with_index do |word, i|
        result[i * 4] = ((word >> 24) & 0xff).to_u8
        result[i * 4 + 1] = ((word >> 16) & 0xff).to_u8
        result[i * 4 + 2] = ((word >> 8) & 0xff).to_u8
        result[i * 4 + 3] = (word & 0xff).to_u8
      end
      
      result
    end
    
    def output_size : Int32
      # SHA-256 output size
      32
    end
    
    def block_size : Int32
      # SHA-256 block size
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
      # Create a 64-entry message schedule array w[0..63] of 32-bit words
      w = Array(UInt32).new(64, 0_u32)
      
      # Copy chunk into first 16 words of the message schedule array
      16.times do |i|
        w[i] = (chunk[i * 4].to_u32 << 24) |
               (chunk[i * 4 + 1].to_u32 << 16) |
               (chunk[i * 4 + 2].to_u32 << 8) |
               chunk[i * 4 + 3].to_u32
      end
      
      # Extend the first 16 words into the remaining 48 words of the message schedule array
      (16..63).each do |i|
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] &+ s0 &+ w[i - 7] &+ s1) & 0xffffffff_u32
      end
      
      # Initialize working variables for this chunk
      a, b, c, d, e, f, g, h_var = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
      
      # Compression function main loop
      64.times do |i|
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h_var &+ s1 &+ ch &+ K[i] &+ w[i]) & 0xffffffff_u32
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 &+ maj) & 0xffffffff_u32
        
        h_var = g
        g = f
        f = e
        e = (d &+ temp1) & 0xffffffff_u32
        d = c
        c = b
        b = a
        a = (temp1 &+ temp2) & 0xffffffff_u32
      end
      
      # Add the compressed chunk to the current hash value
      h[0] = (h[0] &+ a) & 0xffffffff_u32
      h[1] = (h[1] &+ b) & 0xffffffff_u32
      h[2] = (h[2] &+ c) & 0xffffffff_u32
      h[3] = (h[3] &+ d) & 0xffffffff_u32
      h[4] = (h[4] &+ e) & 0xffffffff_u32
      h[5] = (h[5] &+ f) & 0xffffffff_u32
      h[6] = (h[6] &+ g) & 0xffffffff_u32
      h[7] = (h[7] &+ h_var) & 0xffffffff_u32
    end
    
    private def rotr(value : UInt32, amount : Int32) : UInt32
      ((value >> amount) | (value << (32 - amount))) & 0xffffffff_u32
    end
  end
end