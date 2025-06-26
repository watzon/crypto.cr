require "../base/kdf"

module Crypto::KDF
  class ScryptJane < PasswordBasedKDF
    def derive(password : String | Bytes, salt : String | Bytes, output_length : Int32) : Bytes
      raise NotImplementedError.new("ScryptJane algorithm is not yet implemented")
    end

    def iterations : Int32
      16384 # Placeholder value for scrypt-jane
    end
  end
end