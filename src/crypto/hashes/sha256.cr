require "../base/hash_algorithm"

module Crypto::Hashes
  class Sha256 < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Sha256 algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Sha256 algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # SHA-256 output size
      32
    end
    
    def block_size : Int32
      # SHA-256 block size
      64
    end
  end
end