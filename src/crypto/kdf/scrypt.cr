require "openssl"
require "openssl/hmac"
require "openssl/pkcs5"
require "../base/kdf"

module Crypto::KDF
  class SCrypt < PasswordBasedKDF
    # Default parameters
    DEFAULT_N = 14
    DEFAULT_R = 8
    DEFAULT_P = 1
    
    @n : Int32
    @r : Int32
    @p : Int32
    
    def initialize(@n = DEFAULT_N, @r = DEFAULT_R, @p = DEFAULT_P)
    end
    
    # Returns the number of iterations (2^n)
    def iterations : Int32
      1 << @n
    end
    
    # Main KDF interface method
    def derive(password : String | Bytes, salt : Bytes, output_length : Int32) : Bytes
      self.class.hash(password, salt, @n, @r, @p, output_length)
    end
    
    # Legacy static method for backward compatibility
    def self.hash(password, salt, n = DEFAULT_N, r = DEFAULT_R, p = DEFAULT_P, output_length = 64)
      n = 1 << n
      block_size = 128 * r

      b = SCrypt.pbkdf2_sha256(password, salt, 1, block_size * p).to_a
      b = b.each_slice((b.size // p)).to_a

      0.upto(p - 1) do |i|
        b[i] = SCrypt.ro_mix(b[i], n, n).to_a
      end

      b = b.flatten
      expensive_salt = b.to_unsafe.to_slice(b.size)

      SCrypt.pbkdf2_sha256(password, expensive_salt, 1, output_length)
    end

    def self.salsa20_8(input)
      x = input

      rounds = [
        {4, 0, 12, 7}, {8, 4, 0, 9}, {12, 8, 4, 13}, {0, 12, 8, 18},
        {9, 5, 1, 7}, {13, 9, 5, 9}, {1, 13, 9, 13}, {5, 1, 13, 18},
        {14, 10, 6, 7}, {2, 14, 10, 9}, {6, 2, 14, 13}, {10, 6, 2, 18},
        {3, 15, 11, 7}, {7, 3, 15, 9}, {11, 7, 3, 13}, {15, 11, 7, 18},
        {1, 0, 3, 7}, {2, 1, 0, 9}, {3, 2, 1, 13}, {0, 3, 2, 18},
        {6, 5, 4, 7}, {7, 6, 5, 9}, {4, 7, 6, 13}, {5, 4, 7, 18},
        {11, 10, 9, 7}, {8, 11, 10, 9}, {9, 8, 11, 13}, {10, 9, 8, 18},
        {12, 15, 14, 7}, {13, 12, 15, 9}, {14, 13, 12, 13}, {15, 14, 13, 18},
      ]

      rounds.each do |round|
        destination, a1, a2, b = round
        a = x[a1] &+ x[a2]
        x[destination] ^= ((a << b) | (a >> (32 - b))) & 0xffffffff
      end

      return x
    end

    def self.xor(x, y)
      zipped = x.zip(y)
      zipped.map { |o| o[0] ^ o[1] }
    end

    def self.block_mix(input)
      raise "Input's length must me a multiple of 128. Got #{input.size}" unless input.size % 128 == 0

      r = input.size // 128

      b = input.each_slice((input.size // (2 * r))).to_a

      x = b[2 * r - 1]
      y = [] of Array(UInt8)

      (2 * r).times do |i|
        x = salsa20_8(xor(x, b[i]))
        y.push x
      end

      return y.each_slice(2).to_a.transpose.flatten
    end

    def self.ro_mix(block, iterations, n_factor)
      x = block.to_a

      v = [] of Array(UInt8)

      iterations.times do |i|
        v.push x
        x = block_mix(x)
      end

      iterations.times do |i|
        break if i == 0
        j = integerify(x, n_factor)
        x = block_mix(xor(x, v[j]))
      end

      return x.to_unsafe.to_slice(x.size)
    end

    def self.integerify(x, n_factor)
      mask = n_factor - 1
      arr = x[x.size - 64..(x.size) - 60]
      bytes = arr.to_unsafe.to_slice(arr.size)
      int = IO::ByteFormat::LittleEndian.decode(UInt32, bytes)
      int & mask
    end

    def self.sha256(message)
      sha256 = OpenSSL::Digest.new("SHA256")
      sha256.update(message)
      return sha256.digest
    end

    def self.hmac_sha256(message, key)
      return OpenSSL::HMAC.digest(:sha256, key, message)
    end

    def self.pbkdf2_sha256(password, salt, iters, dkLen)
      return OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iters, OpenSSL::Algorithm::SHA256, dkLen)
    end
  end
end