require "../base/kdf"

module Crypto::KDF
  class ScryptN < PasswordBasedKDF
    def derive(password : String | Bytes, salt : String | Bytes, output_length : Int32) : Bytes
      raise NotImplementedError.new("ScryptN algorithm is not yet implemented")
    end

    def iterations : Int32
      32768 # Placeholder value for scrypt-n
    end
  end
end