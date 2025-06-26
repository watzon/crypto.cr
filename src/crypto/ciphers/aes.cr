require "../base/cipher"

module Crypto::Ciphers
  # AES (Advanced Encryption Standard) block cipher implementation
  # Supports 128, 192, and 256-bit key sizes
  class AES < Crypto::Cipher
    # AES S-box (substitution box)
    private SBOX = StaticArray[
      0x63_u8, 0x7c_u8, 0x77_u8, 0x7b_u8, 0xf2_u8, 0x6b_u8, 0x6f_u8, 0xc5_u8,
      0x30_u8, 0x01_u8, 0x67_u8, 0x2b_u8, 0xfe_u8, 0xd7_u8, 0xab_u8, 0x76_u8,
      0xca_u8, 0x82_u8, 0xc9_u8, 0x7d_u8, 0xfa_u8, 0x59_u8, 0x47_u8, 0xf0_u8,
      0xad_u8, 0xd4_u8, 0xa2_u8, 0xaf_u8, 0x9c_u8, 0xa4_u8, 0x72_u8, 0xc0_u8,
      0xb7_u8, 0xfd_u8, 0x93_u8, 0x26_u8, 0x36_u8, 0x3f_u8, 0xf7_u8, 0xcc_u8,
      0x34_u8, 0xa5_u8, 0xe5_u8, 0xf1_u8, 0x71_u8, 0xd8_u8, 0x31_u8, 0x15_u8,
      0x04_u8, 0xc7_u8, 0x23_u8, 0xc3_u8, 0x18_u8, 0x96_u8, 0x05_u8, 0x9a_u8,
      0x07_u8, 0x12_u8, 0x80_u8, 0xe2_u8, 0xeb_u8, 0x27_u8, 0xb2_u8, 0x75_u8,
      0x09_u8, 0x83_u8, 0x2c_u8, 0x1a_u8, 0x1b_u8, 0x6e_u8, 0x5a_u8, 0xa0_u8,
      0x52_u8, 0x3b_u8, 0xd6_u8, 0xb3_u8, 0x29_u8, 0xe3_u8, 0x2f_u8, 0x84_u8,
      0x53_u8, 0xd1_u8, 0x00_u8, 0xed_u8, 0x20_u8, 0xfc_u8, 0xb1_u8, 0x5b_u8,
      0x6a_u8, 0xcb_u8, 0xbe_u8, 0x39_u8, 0x4a_u8, 0x4c_u8, 0x58_u8, 0xcf_u8,
      0xd0_u8, 0xef_u8, 0xaa_u8, 0xfb_u8, 0x43_u8, 0x4d_u8, 0x33_u8, 0x85_u8,
      0x45_u8, 0xf9_u8, 0x02_u8, 0x7f_u8, 0x50_u8, 0x3c_u8, 0x9f_u8, 0xa8_u8,
      0x51_u8, 0xa3_u8, 0x40_u8, 0x8f_u8, 0x92_u8, 0x9d_u8, 0x38_u8, 0xf5_u8,
      0xbc_u8, 0xb6_u8, 0xda_u8, 0x21_u8, 0x10_u8, 0xff_u8, 0xf3_u8, 0xd2_u8,
      0xcd_u8, 0x0c_u8, 0x13_u8, 0xec_u8, 0x5f_u8, 0x97_u8, 0x44_u8, 0x17_u8,
      0xc4_u8, 0xa7_u8, 0x7e_u8, 0x3d_u8, 0x64_u8, 0x5d_u8, 0x19_u8, 0x73_u8,
      0x60_u8, 0x81_u8, 0x4f_u8, 0xdc_u8, 0x22_u8, 0x2a_u8, 0x90_u8, 0x88_u8,
      0x46_u8, 0xee_u8, 0xb8_u8, 0x14_u8, 0xde_u8, 0x5e_u8, 0x0b_u8, 0xdb_u8,
      0xe0_u8, 0x32_u8, 0x3a_u8, 0x0a_u8, 0x49_u8, 0x06_u8, 0x24_u8, 0x5c_u8,
      0xc2_u8, 0xd3_u8, 0xac_u8, 0x62_u8, 0x91_u8, 0x95_u8, 0xe4_u8, 0x79_u8,
      0xe7_u8, 0xc8_u8, 0x37_u8, 0x6d_u8, 0x8d_u8, 0xd5_u8, 0x4e_u8, 0xa9_u8,
      0x6c_u8, 0x56_u8, 0xf4_u8, 0xea_u8, 0x65_u8, 0x7a_u8, 0xae_u8, 0x08_u8,
      0xba_u8, 0x78_u8, 0x25_u8, 0x2e_u8, 0x1c_u8, 0xa6_u8, 0xb4_u8, 0xc6_u8,
      0xe8_u8, 0xdd_u8, 0x74_u8, 0x1f_u8, 0x4b_u8, 0xbd_u8, 0x8b_u8, 0x8a_u8,
      0x70_u8, 0x3e_u8, 0xb5_u8, 0x66_u8, 0x48_u8, 0x03_u8, 0xf6_u8, 0x0e_u8,
      0x61_u8, 0x35_u8, 0x57_u8, 0xb9_u8, 0x86_u8, 0xc1_u8, 0x1d_u8, 0x9e_u8,
      0xe1_u8, 0xf8_u8, 0x98_u8, 0x11_u8, 0x69_u8, 0xd9_u8, 0x8e_u8, 0x94_u8,
      0x9b_u8, 0x1e_u8, 0x87_u8, 0xe9_u8, 0xce_u8, 0x55_u8, 0x28_u8, 0xdf_u8,
      0x8c_u8, 0xa1_u8, 0x89_u8, 0x0d_u8, 0xbf_u8, 0xe6_u8, 0x42_u8, 0x68_u8,
      0x41_u8, 0x99_u8, 0x2d_u8, 0x0f_u8, 0xb0_u8, 0x54_u8, 0xbb_u8, 0x16_u8
    ]

    # AES inverse S-box for decryption
    private INV_SBOX = StaticArray[
      0x52_u8, 0x09_u8, 0x6a_u8, 0xd5_u8, 0x30_u8, 0x36_u8, 0xa5_u8, 0x38_u8,
      0xbf_u8, 0x40_u8, 0xa3_u8, 0x9e_u8, 0x81_u8, 0xf3_u8, 0xd7_u8, 0xfb_u8,
      0x7c_u8, 0xe3_u8, 0x39_u8, 0x82_u8, 0x9b_u8, 0x2f_u8, 0xff_u8, 0x87_u8,
      0x34_u8, 0x8e_u8, 0x43_u8, 0x44_u8, 0xc4_u8, 0xde_u8, 0xe9_u8, 0xcb_u8,
      0x54_u8, 0x7b_u8, 0x94_u8, 0x32_u8, 0xa6_u8, 0xc2_u8, 0x23_u8, 0x3d_u8,
      0xee_u8, 0x4c_u8, 0x95_u8, 0x0b_u8, 0x42_u8, 0xfa_u8, 0xc3_u8, 0x4e_u8,
      0x08_u8, 0x2e_u8, 0xa1_u8, 0x66_u8, 0x28_u8, 0xd9_u8, 0x24_u8, 0xb2_u8,
      0x76_u8, 0x5b_u8, 0xa2_u8, 0x49_u8, 0x6d_u8, 0x8b_u8, 0xd1_u8, 0x25_u8,
      0x72_u8, 0xf8_u8, 0xf6_u8, 0x64_u8, 0x86_u8, 0x68_u8, 0x98_u8, 0x16_u8,
      0xd4_u8, 0xa4_u8, 0x5c_u8, 0xcc_u8, 0x5d_u8, 0x65_u8, 0xb6_u8, 0x92_u8,
      0x6c_u8, 0x70_u8, 0x48_u8, 0x50_u8, 0xfd_u8, 0xed_u8, 0xb9_u8, 0xda_u8,
      0x5e_u8, 0x15_u8, 0x46_u8, 0x57_u8, 0xa7_u8, 0x8d_u8, 0x9d_u8, 0x84_u8,
      0x90_u8, 0xd8_u8, 0xab_u8, 0x00_u8, 0x8c_u8, 0xbc_u8, 0xd3_u8, 0x0a_u8,
      0xf7_u8, 0xe4_u8, 0x58_u8, 0x05_u8, 0xb8_u8, 0xb3_u8, 0x45_u8, 0x06_u8,
      0xd0_u8, 0x2c_u8, 0x1e_u8, 0x8f_u8, 0xca_u8, 0x3f_u8, 0x0f_u8, 0x02_u8,
      0xc1_u8, 0xaf_u8, 0xbd_u8, 0x03_u8, 0x01_u8, 0x13_u8, 0x8a_u8, 0x6b_u8,
      0x3a_u8, 0x91_u8, 0x11_u8, 0x41_u8, 0x4f_u8, 0x67_u8, 0xdc_u8, 0xea_u8,
      0x97_u8, 0xf2_u8, 0xcf_u8, 0xce_u8, 0xf0_u8, 0xb4_u8, 0xe6_u8, 0x73_u8,
      0x96_u8, 0xac_u8, 0x74_u8, 0x22_u8, 0xe7_u8, 0xad_u8, 0x35_u8, 0x85_u8,
      0xe2_u8, 0xf9_u8, 0x37_u8, 0xe8_u8, 0x1c_u8, 0x75_u8, 0xdf_u8, 0x6e_u8,
      0x47_u8, 0xf1_u8, 0x1a_u8, 0x71_u8, 0x1d_u8, 0x29_u8, 0xc5_u8, 0x89_u8,
      0x6f_u8, 0xb7_u8, 0x62_u8, 0x0e_u8, 0xaa_u8, 0x18_u8, 0xbe_u8, 0x1b_u8,
      0xfc_u8, 0x56_u8, 0x3e_u8, 0x4b_u8, 0xc6_u8, 0xd2_u8, 0x79_u8, 0x20_u8,
      0x9a_u8, 0xdb_u8, 0xc0_u8, 0xfe_u8, 0x78_u8, 0xcd_u8, 0x5a_u8, 0xf4_u8,
      0x1f_u8, 0xdd_u8, 0xa8_u8, 0x33_u8, 0x88_u8, 0x07_u8, 0xc7_u8, 0x31_u8,
      0xb1_u8, 0x12_u8, 0x10_u8, 0x59_u8, 0x27_u8, 0x80_u8, 0xec_u8, 0x5f_u8,
      0x60_u8, 0x51_u8, 0x7f_u8, 0xa9_u8, 0x19_u8, 0xb5_u8, 0x4a_u8, 0x0d_u8,
      0x2d_u8, 0xe5_u8, 0x7a_u8, 0x9f_u8, 0x93_u8, 0xc9_u8, 0x9c_u8, 0xef_u8,
      0xa0_u8, 0xe0_u8, 0x3b_u8, 0x4d_u8, 0xae_u8, 0x2a_u8, 0xf5_u8, 0xb0_u8,
      0xc8_u8, 0xeb_u8, 0xbb_u8, 0x3c_u8, 0x83_u8, 0x53_u8, 0x99_u8, 0x61_u8,
      0x17_u8, 0x2b_u8, 0x04_u8, 0x7e_u8, 0xba_u8, 0x77_u8, 0xd6_u8, 0x26_u8,
      0xe1_u8, 0x69_u8, 0x14_u8, 0x63_u8, 0x55_u8, 0x21_u8, 0x0c_u8, 0x7d_u8
    ]

    # Round constants for key expansion
    private RCON = StaticArray[
      0x01_u8, 0x02_u8, 0x04_u8, 0x08_u8, 0x10_u8, 0x20_u8, 0x40_u8, 0x80_u8,
      0x1b_u8, 0x36_u8, 0x6c_u8, 0xd8_u8, 0xab_u8, 0x4d_u8, 0x9a_u8
    ]

    private getter expanded_key : Bytes
    private getter rounds : Int32
    private getter nk : Int32  # Number of 32-bit words in the key
    
    @key_size : Int32

    def initialize(@key : Bytes)
      case @key.size
      when 16
        @key_size = 16
        @rounds = 10
        @nk = 4
      when 24
        @key_size = 24
        @rounds = 12
        @nk = 6
      when 32
        @key_size = 32
        @rounds = 14
        @nk = 8
      else
        raise ArgumentError.new("Invalid AES key size: #{@key.size} bytes. Must be 16, 24, or 32 bytes.")
      end

      @expanded_key = Bytes.new(4 * 4 * (@rounds + 1))
      expand_key
    end

    def encrypt(data : Bytes) : Bytes
      if data.size != 16
        raise ArgumentError.new("AES operates on 16-byte blocks. Input size: #{data.size}")
      end

      # Create a working copy
      state = Bytes.new(16)
      data.copy_to(state)
      
      # Initial round key addition
      add_round_key(state, 0)
      
      # Main rounds
      (1...@rounds).each do |round|
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round)
      end
      
      # Final round (no MixColumns)
      sub_bytes(state)
      shift_rows(state)
      add_round_key(state, @rounds)
      
      state
    end

    def decrypt(data : Bytes) : Bytes
      if data.size != 16
        raise ArgumentError.new("AES operates on 16-byte blocks. Input size: #{data.size}")
      end

      # Create a working copy
      state = Bytes.new(16)
      data.copy_to(state)
      
      # Initial round key addition
      add_round_key(state, @rounds)
      
      # Main rounds (in reverse)
      (@rounds - 1).downto(1) do |round|
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round)
        inv_mix_columns(state)
      end
      
      # Final round
      inv_shift_rows(state)
      inv_sub_bytes(state)
      add_round_key(state, 0)
      
      state
    end

    def block_size : Int32
      16  # AES always operates on 128-bit (16-byte) blocks
    end

    def key_size : Int32
      @key_size
    end

    # Key expansion algorithm
    private def expand_key
      # Copy the original key
      @key.copy_to(@expanded_key)

      # Generate the expanded key
      bytes_generated = @key_size
      rcon_index = 0

      while bytes_generated < @expanded_key.size
        # Create a 4-byte temporary variable
        temp = StaticArray(UInt8, 4).new(0_u8)
        4.times do |i|
          temp[i] = @expanded_key[bytes_generated - 4 + i]
        end

        # Every Nk words, apply transformation
        if bytes_generated % @key_size == 0
          # Rotate word
          temp = rotate_word(temp)
          # SubBytes
          4.times { |i| temp[i] = SBOX[temp[i]] }
          # XOR with round constant
          temp[0] ^= RCON[rcon_index]
          rcon_index += 1
        elsif @nk > 6 && bytes_generated % @key_size == 16
          # Additional transformation for 256-bit keys
          4.times { |i| temp[i] = SBOX[temp[i]] }
        end

        # XOR with the word Nk positions earlier
        4.times do |i|
          @expanded_key[bytes_generated] = @expanded_key[bytes_generated - @key_size] ^ temp[i]
          bytes_generated += 1
        end
      end
    end

    # Rotate word for key expansion
    private def rotate_word(word : StaticArray(UInt8, 4)) : StaticArray(UInt8, 4)
      StaticArray[word[1], word[2], word[3], word[0]]
    end

    # SubBytes transformation
    private def sub_bytes(state : Bytes)
      state.size.times { |i| state[i] = SBOX[state[i]] }
    end

    # Inverse SubBytes transformation
    private def inv_sub_bytes(state : Bytes)
      state.size.times { |i| state[i] = INV_SBOX[state[i]] }
    end

    # ShiftRows transformation
    private def shift_rows(state : Bytes)
      # Row 1: shift left by 1
      temp = state[1]
      state[1] = state[5]
      state[5] = state[9]
      state[9] = state[13]
      state[13] = temp

      # Row 2: shift left by 2
      temp = state[2]
      state[2] = state[10]
      state[10] = temp
      temp = state[6]
      state[6] = state[14]
      state[14] = temp

      # Row 3: shift left by 3
      temp = state[15]
      state[15] = state[11]
      state[11] = state[7]
      state[7] = state[3]
      state[3] = temp
    end

    # Inverse ShiftRows transformation
    private def inv_shift_rows(state : Bytes)
      # Row 1: shift right by 1
      temp = state[13]
      state[13] = state[9]
      state[9] = state[5]
      state[5] = state[1]
      state[1] = temp

      # Row 2: shift right by 2
      temp = state[2]
      state[2] = state[10]
      state[10] = temp
      temp = state[6]
      state[6] = state[14]
      state[14] = temp

      # Row 3: shift right by 3
      temp = state[3]
      state[3] = state[7]
      state[7] = state[11]
      state[11] = state[15]
      state[15] = temp
    end

    # Galois field multiplication
    private def gmul(a : UInt8, b : UInt8) : UInt8
      p = 0_u8
      8.times do
        if (b & 1) != 0
          p ^= a
        end
        hi_bit = a & 0x80
        a <<= 1
        if hi_bit != 0
          a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
        end
        b >>= 1
      end
      p
    end

    # MixColumns transformation
    private def mix_columns(state : Bytes)
      4.times do |i|
        col_start = i * 4
        a = state[col_start]
        b = state[col_start + 1]
        c = state[col_start + 2]
        d = state[col_start + 3]

        state[col_start] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d
        state[col_start + 1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d
        state[col_start + 2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3)
        state[col_start + 3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2)
      end
    end

    # Inverse MixColumns transformation
    private def inv_mix_columns(state : Bytes)
      4.times do |i|
        col_start = i * 4
        a = state[col_start]
        b = state[col_start + 1]
        c = state[col_start + 2]
        d = state[col_start + 3]

        state[col_start] = gmul(a, 0x0e) ^ gmul(b, 0x0b) ^ gmul(c, 0x0d) ^ gmul(d, 0x09)
        state[col_start + 1] = gmul(a, 0x09) ^ gmul(b, 0x0e) ^ gmul(c, 0x0b) ^ gmul(d, 0x0d)
        state[col_start + 2] = gmul(a, 0x0d) ^ gmul(b, 0x09) ^ gmul(c, 0x0e) ^ gmul(d, 0x0b)
        state[col_start + 3] = gmul(a, 0x0b) ^ gmul(b, 0x0d) ^ gmul(c, 0x09) ^ gmul(d, 0x0e)
      end
    end

    # AddRoundKey transformation
    private def add_round_key(state : Bytes, round : Int32)
      key_offset = round * 16
      16.times do |i|
        state[i] ^= @expanded_key[key_offset + i]
      end
    end
  end
end