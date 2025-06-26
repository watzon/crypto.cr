require "../base/hash_algorithm"

module Crypto::Hashes
  class Fugue < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Fugue algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Fugue algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # Fugue-256 default output size
      32
    end
    
    def block_size : Int32
      # Fugue-256 default block size
      30
    end
  end
end