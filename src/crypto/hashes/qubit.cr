require "../base/hash_algorithm"

module Crypto::Hashes
  class Qubit < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Qubit algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Qubit algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # Qubit default output size
      32
    end
    
    def block_size : Int32
      # Qubit uses multiple algorithms, this is a composite value
      64
    end
  end
end