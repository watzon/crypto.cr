require "../base/hash_algorithm"

module Crypto::Hashes
  class X15 < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("X15 algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("X15 algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # X15 chain output size
      32
    end
    
    def block_size : Int32
      # X15 uses multiple algorithms, this is a composite value
      64
    end
  end
end