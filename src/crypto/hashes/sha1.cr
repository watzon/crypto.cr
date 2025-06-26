require "../base/hash_algorithm"

module Crypto::Hashes
  class Sha1 < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Sha1 algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Sha1 algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # SHA-1 output size
      20
    end
    
    def block_size : Int32
      # SHA-1 block size
      64
    end
  end
end