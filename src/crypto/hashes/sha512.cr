require "../base/hash_algorithm"

module Crypto::Hashes
  class Sha512 < Crypto::HashAlgorithm
    # SHA-512 constants (first 64 bits of the fractional parts of the cube roots of the first 80 primes)
    private K = [
      0x428a2f98d728ae22_u64, 0x7137449123ef65cd_u64, 0xb5c0fbcfec4d3b2f_u64, 0xe9b5dba58189dbbc_u64,
      0x3956c25bf348b538_u64, 0x59f111f1b605d019_u64, 0x923f82a4af194f9b_u64, 0xab1c5ed5da6d8118_u64,
      0xd807aa98a3030242_u64, 0x12835b0145706fbe_u64, 0x243185be4ee4b28c_u64, 0x550c7dc3d5ffb4e2_u64,
      0x72be5d74f27b896f_u64, 0x80deb1fe3b1696b1_u64, 0x9bdc06a725c71235_u64, 0xc19bf174cf692694_u64,
      0xe49b69c19ef14ad2_u64, 0xefbe4786384f25e3_u64, 0x0fc19dc68b8cd5b5_u64, 0x240ca1cc77ac9c65_u64,
      0x2de92c6f592b0275_u64, 0x4a7484aa6ea6e483_u64, 0x5cb0a9dcbd41fbd4_u64, 0x76f988da831153b5_u64,
      0x983e5152ee66dfab_u64, 0xa831c66d2db43210_u64, 0xb00327c898fb213f_u64, 0xbf597fc7beef0ee4_u64,
      0xc6e00bf33da88fc2_u64, 0xd5a79147930aa725_u64, 0x06ca6351e003826f_u64, 0x142929670a0e6e70_u64,
      0x27b70a8546d22ffc_u64, 0x2e1b21385c26c926_u64, 0x4d2c6dfc5ac42aed_u64, 0x53380d139d95b3df_u64,
      0x650a73548baf63de_u64, 0x766a0abb3c77b2a8_u64, 0x81c2c92e47edaee6_u64, 0x92722c851482353b_u64,
      0xa2bfe8a14cf10364_u64, 0xa81a664bbc423001_u64, 0xc24b8b70d0f89791_u64, 0xc76c51a30654be30_u64,
      0xd192e819d6ef5218_u64, 0xd69906245565a910_u64, 0xf40e35855771202a_u64, 0x106aa07032bbd1b8_u64,
      0x19a4c116b8d2d0c8_u64, 0x1e376c085141ab53_u64, 0x2748774cdf8eeb99_u64, 0x34b0bcb5e19b48a8_u64,
      0x391c0cb3c5c95a63_u64, 0x4ed8aa4ae3418acb_u64, 0x5b9cca4f7763e373_u64, 0x682e6ff3d6b2b8a3_u64,
      0x748f82ee5defb2fc_u64, 0x78a5636f43172f60_u64, 0x84c87814a1f0ab72_u64, 0x8cc702081a6439ec_u64,
      0x90befffa23631e28_u64, 0xa4506cebde82bde9_u64, 0xbef9a3f7b2c67915_u64, 0xc67178f2e372532b_u64,
      0xca273eceea26619c_u64, 0xd186b8c721c0c207_u64, 0xeada7dd6cde0eb1e_u64, 0xf57d4f7fee6ed178_u64,
      0x06f067aa72176fba_u64, 0x0a637dc5a2c898a6_u64, 0x113f9804bef90dae_u64, 0x1b710b35131c471b_u64,
      0x28db77f523047d84_u64, 0x32caab7b40c72493_u64, 0x3c9ebe0a15c9bebc_u64, 0x431d67c49c100d4c_u64,
      0x4cc5d4becb3e42b6_u64, 0x597f299cfc657e2a_u64, 0x5fcb6fab3ad6faec_u64, 0x6c44198c4a475817_u64
    ]
    
    # Initial hash values (first 64 bits of the fractional parts of the square roots of the first 8 primes)
    private H0 = [
      0x6a09e667f3bcc908_u64, 0xbb67ae8584caa73b_u64, 0x3c6ef372fe94f82b_u64, 0xa54ff53a5f1d36f1_u64,
      0x510e527fade682d1_u64, 0x9b05688c2b3e6c1f_u64, 0x1f83d9abfb41bd6b_u64, 0x5be0cd19137e2179_u64
    ]
    
    def hash(input : String) : String
      hash_bytes(input.to_slice).hexstring
    end
    
    def hash_bytes(input : Bytes) : Bytes
      # Initialize hash values
      h = H0.dup
      
      # Pre-processing: adding padding bits
      message = preprocess(input)
      
      # Process the message in successive 1024-bit chunks
      (0...message.size).step(128) do |chunk_start|
        chunk = message[chunk_start, 128]
        process_chunk(chunk, h)
      end
      
      # Produce the final hash value as a 512-bit number (64 bytes)
      result = Bytes.new(64)
      h.each_with_index do |word, i|
        result[i * 8] = ((word >> 56) & 0xff).to_u8
        result[i * 8 + 1] = ((word >> 48) & 0xff).to_u8
        result[i * 8 + 2] = ((word >> 40) & 0xff).to_u8
        result[i * 8 + 3] = ((word >> 32) & 0xff).to_u8
        result[i * 8 + 4] = ((word >> 24) & 0xff).to_u8
        result[i * 8 + 5] = ((word >> 16) & 0xff).to_u8
        result[i * 8 + 6] = ((word >> 8) & 0xff).to_u8
        result[i * 8 + 7] = (word & 0xff).to_u8
      end
      
      result
    end
    
    def output_size : Int32
      # SHA-512 output size
      64
    end
    
    def block_size : Int32
      # SHA-512 block size
      128
    end
    
    private def preprocess(input : Bytes) : Bytes
      # Pre-processing: adding padding bits
      message_len = input.size
      
      # append the '1' bit (0x80)
      message = input + Bytes[0x80]
      
      # append 0 <= k < 1024 bits '0', such that the resulting message length in bits
      # is congruent to 896 (mod 1024)
      while (message.size % 128) != 112
        message += Bytes[0x00]
      end
      
      # append original length in bits mod 2^128 to message as 128-bit big-endian integer
      # For simplicity, we only handle messages shorter than 2^64 bits, so high 64 bits are 0
      bit_len = message_len.to_u64 * 8
      
      # First append 8 zero bytes (high 64 bits)
      8.times do
        message += Bytes[0x00]
      end
      
      # Then append the actual length as 64-bit big-endian
      8.times do |i|
        message += Bytes[((bit_len >> (56 - i * 8)) & 0xff).to_u8]
      end
      
      message
    end
    
    private def process_chunk(chunk : Bytes, h : Array(UInt64))
      # Create a 80-entry message schedule array w[0..79] of 64-bit words
      w = Array(UInt64).new(80, 0_u64)
      
      # Copy chunk into first 16 words of the message schedule array
      16.times do |i|
        w[i] = (chunk[i * 8].to_u64 << 56) |
               (chunk[i * 8 + 1].to_u64 << 48) |
               (chunk[i * 8 + 2].to_u64 << 40) |
               (chunk[i * 8 + 3].to_u64 << 32) |
               (chunk[i * 8 + 4].to_u64 << 24) |
               (chunk[i * 8 + 5].to_u64 << 16) |
               (chunk[i * 8 + 6].to_u64 << 8) |
               chunk[i * 8 + 7].to_u64
      end
      
      # Extend the first 16 words into the remaining 64 words of the message schedule array
      (16..79).each do |i|
        s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
        s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
        w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
      end
      
      # Initialize working variables for this chunk
      a, b, c, d, e, f, g, h_var = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
      
      # Compression function main loop
      80.times do |i|
        s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
        ch = (e & f) ^ ((~e) & g)
        temp1 = h_var &+ s1 &+ ch &+ K[i] &+ w[i]
        s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = s0 &+ maj
        
        h_var = g
        g = f
        f = e
        e = d &+ temp1
        d = c
        c = b
        b = a
        a = temp1 &+ temp2
      end
      
      # Add the compressed chunk to the current hash value
      h[0] = h[0] &+ a
      h[1] = h[1] &+ b
      h[2] = h[2] &+ c
      h[3] = h[3] &+ d
      h[4] = h[4] &+ e
      h[5] = h[5] &+ f
      h[6] = h[6] &+ g
      h[7] = h[7] &+ h_var
    end
    
    private def rotr64(value : UInt64, amount : Int32) : UInt64
      (value >> amount) | (value << (64 - amount))
    end
  end
end