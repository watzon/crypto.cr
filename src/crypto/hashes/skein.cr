require "../base/hash_algorithm"

module Crypto::Hashes
  class Skein < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Skein algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Skein algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # Skein-512 default output size
      64
    end
    
    def block_size : Int32
      # Skein-512 default block size
      64
    end
  end
end