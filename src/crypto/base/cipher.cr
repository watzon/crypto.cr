module Crypto
  module Ciphers
  end

  # Abstract base class for all symmetric cipher implementations
  abstract class Cipher
    # Encrypts the given data
    abstract def encrypt(data : Bytes) : Bytes

    # Decrypts the given data
    abstract def decrypt(data : Bytes) : Bytes

    # Encrypts a string and returns bytes
    def encrypt(data : String) : Bytes
      encrypt(data.to_slice)
    end

    # Decrypts bytes and returns a string
    def decrypt_string(data : Bytes) : String
      String.new(decrypt(data))
    end

    # Returns the block size in bytes
    abstract def block_size : Int32

    # Returns the key size in bytes
    abstract def key_size : Int32
  end

  # Abstract base class for block cipher modes
  abstract class BlockCipherMode < Cipher
    abstract def initialize(key : Bytes, iv : Bytes)
  end

  # Abstract base class for stream ciphers
  abstract class StreamCipher < Cipher
    # Stream ciphers don't have a fixed block size
    def block_size : Int32
      1
    end
  end
end
