module Crypto
  module Hashes
  end
  
  # Abstract base class for all hash algorithm implementations
  abstract class HashAlgorithm
    # Hashes a string and returns a hex string
    abstract def hash(input : String) : String
    
    # Hashes bytes and returns bytes
    abstract def hash_bytes(input : Bytes) : Bytes
    
    # Hashes a string and returns bytes
    def hash_bytes(input : String) : Bytes
      hash_bytes(input.to_slice)
    end
    
    # Returns the output size in bytes
    abstract def output_size : Int32
    
    # Returns the block size in bytes
    abstract def block_size : Int32
  end
end
