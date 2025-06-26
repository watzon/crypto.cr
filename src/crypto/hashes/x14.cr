require "../base/hash_algorithm"

module Crypto::Hashes
  class X14 < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("X14 algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("X14 algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # X14 chain output size
      32
    end
    
    def block_size : Int32
      # X14 uses multiple algorithms, this is a composite value
      64
    end
  end
end