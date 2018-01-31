require "openssl"
require "openssl/hmac"
require "openssl/pkcs5"

module Crypto::Algorithms
  class SCrypt < HashAlgorithm

    def initialize(@log_n : Int32, @r : Int32, @p : Int32)

    end

    def hash(password, salt, output_length)
      n = 1 << @log_n
      r128 = @r * 128
      pr128 = @p * r128
      nr128 = n * r128

      mac = SCrypt.sha256(password)

      b = Slice(UInt8).new(pr128)
      b = SCrypt.pbkdf2_sha256(mac, salt, 1, b.size)

      v = Slice(UInt8).new(nr128)
      t = Slice(UInt8).new(r128)

      q = Array(UInt8).new(pr128)
      b.each_slice(r128) do |chunk|
        chunk = SCrypt.scrypt_ro_mix(chunk, v, t, n)
        q.concat(chunk)
      end
      q = q.to_unsafe.to_slice(q.size)

      SCrypt.pbkdf2_sha256(mac, q, 1, output_length)
    end

    def self.salsa20_8(input)
      x = input

      rounds = [
          {4, 0, 12, 7},   {8, 4, 0, 9},    {12, 8, 4, 13},   {0, 12, 8, 18},
          {9, 5, 1, 7},    {13, 9, 5, 9},   {1, 13, 9, 13},   {5, 1, 13, 18},
          {14, 10, 6, 7},  {2, 14, 10, 9},  {6, 2, 14, 13},   {10, 6, 2, 18},
          {3, 15, 11, 7},  {7, 3, 15, 9},   {11, 7, 3, 13},   {15, 11, 7, 18},
          {1, 0, 3, 7},    {2, 1, 0, 9},    {3, 2, 1, 13},    {0, 3, 2, 18},
          {6, 5, 4, 7},    {7, 6, 5, 9},    {4, 7, 6, 13},    {5, 4, 7, 18},
          {11, 10, 9, 7},  {8, 11, 10, 9},  {9, 8, 11, 13},   {10, 9, 8, 18},
          {12, 15, 14, 7}, {13, 12, 15, 9}, {14, 13, 12, 13}, {15, 14, 13, 18},
      ]

      rounds.each do |round|
        destination, a1, a2, b = round
        a = (x[a1] + x[a2]) & 0xffffffff
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

      x = input.last(64)
      output = Array(UInt8).new(input.size, 0.to_u8)

      input.each_slice(64).each_with_index do |chunk, i|
        x = xor(x, chunk)
        x = salsa20_8(x)
        pos = i.even? ? (i / 2) * 64 : (i / 2) * 64 + input.size / 2
        output[pos..pos + 64] = x
      end

      return output
    end

    def self.scrypt_ro_mix(b, v, t, n)
      v.each_slice(b.size) do |chunk|
        chunk = b
        chunk = block_mix(chunk)
      end

      n.times do
        j = integerify(b, n)
        y = v.to_a[j * (b.size), (j + 1) * b.size]
        t = xor(b, y.to_a)
        t = block_mix(b)
      end

      return t
    end

    def self.integerify(x, n)
      mask = n - 1
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
      return OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, iters, dkLen)
    end

  end
end
