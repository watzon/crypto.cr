require "../base/hash_algorithm"

module Crypto::Hashes
  class Groestl < Crypto::HashAlgorithm
    def hash(input : String) : String
      raise NotImplementedError.new("Groestl algorithm is not yet implemented")
    end
    
    def hash_bytes(input : Bytes) : Bytes
      raise NotImplementedError.new("Groestl algorithm is not yet implemented")
    end
    
    def output_size : Int32
      # Groestl-256 default output size
      32
    end
    
    def block_size : Int32
      # Groestl-256 default block size
      64
    end
  end
end