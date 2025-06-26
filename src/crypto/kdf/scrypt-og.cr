require "../base/kdf"

module Crypto::KDF
  class ScryptOg < PasswordBasedKDF
    def derive(password : String | Bytes, salt : String | Bytes, output_length : Int32) : Bytes
      raise NotImplementedError.new("ScryptOg algorithm is not yet implemented")
    end

    def iterations : Int32
      16384 # Placeholder value for scrypt original
    end
  end
end