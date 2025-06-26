require "../base/hash_algorithm"

module Crypto::Hashes
  class Keccak < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Keccak algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Keccak algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # Keccak-256 default output size
      32
    end
    
    def block_size : Int32
      # Keccak-256 default block size
      136
    end
  end
end