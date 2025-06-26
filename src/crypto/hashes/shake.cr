require "../base/hash_algorithm"

module Crypto::Hashes
  # SHAKE (Secure Hash Algorithm Keccak) - Extendable Output Functions
  # This is an educational implementation - not for production use
  class SHAKE < Crypto::HashAlgorithm
    # Keccak round constants
    private ROUND_CONSTANTS = [
      0x0000000000000001_u64, 0x0000000000008082_u64, 0x800000000000808a_u64,
      0x8000000080008000_u64, 0x000000000000808b_u64, 0x0000000080000001_u64,
      0x8000000080008081_u64, 0x8000000000008009_u64, 0x000000000000008a_u64,
      0x0000000000000088_u64, 0x0000000080008009_u64, 0x000000008000000a_u64,
      0x000000008000808b_u64, 0x800000000000008b_u64, 0x8000000000008089_u64,
      0x8000000000008003_u64, 0x8000000000008002_u64, 0x8000000000000080_u64,
      0x000000000000800a_u64, 0x800000008000000a_u64, 0x8000000080008081_u64,
      0x8000000000008080_u64, 0x0000000080000001_u64, 0x8000000080008008_u64
    ]

    # Rotation offsets for rho step - indexed by [x,y]
    private RHO_OFFSETS = [
      [ 0, 36,  3, 41, 18], # x=0
      [ 1, 44, 10, 45,  2], # x=1
      [62,  6, 43, 15, 61], # x=2
      [28, 55, 25, 21, 56], # x=3
      [27, 20, 39,  8, 14]  # x=4
    ]

    @capacity : Int32
    @rate : Int32
    @default_output_length : Int32

    def initialize(capacity_bits : Int32, @default_output_length : Int32)
      @capacity = capacity_bits
      @rate = 1600 - @capacity
      
      unless [256, 512].includes?(capacity_bits)
        raise ArgumentError.new("SHAKE capacity must be 256 or 512 bits")
      end
    end

    def hash(input : String) : String
      hash_bytes(input.to_slice).hexstring
    end

    def hash_bytes(input : Bytes) : Bytes
      shake(input, @default_output_length)
    end

    # Generate output of specified length
    def shake(input : String | Bytes, output_length : Int32) : Bytes
      input_bytes = input.is_a?(String) ? input.to_slice : input
      keccak_shake(input_bytes, output_length)
    end

    def output_size : Int32
      @default_output_length
    end

    def block_size : Int32
      @rate // 8
    end

    # Core Keccak sponge function for SHAKE
    private def keccak_shake(input : Bytes, output_length : Int32) : Bytes
      # Initialize state (25 64-bit words = 1600 bits)
      state = StaticArray(UInt64, 25).new(0_u64)
      
      # Absorbing phase
      rate_bytes = @rate // 8
      input_offset = 0
      
      # Process full blocks
      while input_offset + rate_bytes <= input.size
        # XOR block into state
        (0...rate_bytes).each do |i|
          lane_index = i // 8
          byte_index = i % 8
          state[lane_index] ^= (input[input_offset + i].to_u64 << (byte_index * 8))
        end
        
        # Apply Keccak-f[1600] permutation
        state = keccak_f(state)
        
        input_offset += rate_bytes
      end
      
      # Process final partial block and apply padding
      remaining = input.size - input_offset
      (0...remaining).each do |i|
        lane_index = i // 8
        byte_index = i % 8
        state[lane_index] ^= (input[input_offset + i].to_u64 << (byte_index * 8))
      end
      
      # SHAKE padding (domain separator 0x1F)
      padding_offset = remaining
      state[padding_offset // 8] ^= (0x1F_u64 << ((padding_offset % 8) * 8))
      
      # Apply final padding bit
      state[(rate_bytes - 1) // 8] ^= (0x80_u64 << (((rate_bytes - 1) % 8) * 8))
      
      # Apply final permutation
      state = keccak_f(state)
      
      # Squeezing phase
      output = Bytes.new(output_length)
      output_offset = 0
      
      while output_offset < output_length
        # Extract bytes from state
        extract_size = Math.min(rate_bytes, output_length - output_offset)
        (0...extract_size).each do |i|
          lane_index = i // 8
          byte_index = i % 8
          output[output_offset + i] = ((state[lane_index] >> (byte_index * 8)) & 0xff).to_u8
        end
        
        output_offset += extract_size
        
        # Apply permutation if more output needed
        if output_offset < output_length
          state = keccak_f(state)
        end
      end
      
      output
    end

    # Keccak-f[1600] permutation function
    private def keccak_f(state : StaticArray(UInt64, 25)) : StaticArray(UInt64, 25)
      24.times do |round|
        # θ (Theta) step
        c = StaticArray(UInt64, 5).new(0_u64)
        5.times do |x|
          c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
        end
        
        d = StaticArray(UInt64, 5).new(0_u64)
        5.times do |x|
          d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
        end
        
        25.times do |i|
          state[i] ^= d[i % 5]
        end
        
        # ρ (Rho) and π (Pi) steps
        temp_state = state.dup
        5.times do |x|
          5.times do |y|
            src_index = x + 5 * y
            dst_x = y
            dst_y = (2 * x + 3 * y) % 5
            dst_index = dst_x + 5 * dst_y
            state[dst_index] = rotl(temp_state[src_index], RHO_OFFSETS[x][y])
          end
        end
        
        # χ (Chi) step
        temp_state = state.dup
        5.times do |y|
          5.times do |x|
            index = y * 5 + x
            state[index] = temp_state[index] ^ ((~temp_state[y * 5 + ((x + 1) % 5)]) & temp_state[y * 5 + ((x + 2) % 5)])
          end
        end
        
        # ι (Iota) step
        state[0] ^= ROUND_CONSTANTS[round]
      end
      
      state
    end

    # Left rotation for 64-bit values
    private def rotl(value : UInt64, amount : Int32) : UInt64
      (value << amount) | (value >> (64 - amount))
    end
  end

  # Convenience classes for specific SHAKE variants
  class SHAKE128 < SHAKE
    def initialize(output_length : Int32 = 16)
      super(256, output_length)
    end
  end

  class SHAKE256 < SHAKE
    def initialize(output_length : Int32 = 32)
      super(512, output_length)
    end
  end
end