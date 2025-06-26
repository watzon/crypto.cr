require "../base/hash_algorithm"

module Crypto::Hashes
  class Nist5 < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Nist5 algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Nist5 algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # NIST5 default output size
      64
    end
    
    def block_size : Int32
      # NIST5 uses multiple algorithms, this is a composite value
      64
    end
  end
end