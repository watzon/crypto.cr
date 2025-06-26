module Crypto
  module KDF
  end
  
  # Abstract base class for Key Derivation Functions
  abstract class KeyDerivationFunction
    # Derives a key from the input material
    abstract def derive(password : String | Bytes, salt : Bytes, output_length : Int32) : Bytes
    
    # Helper method to derive a key from a string password
    def derive(password : String, salt : String, output_length : Int32) : Bytes
      derive(password, salt.to_slice, output_length)
    end
  end
  
  # Abstract base class for password-based KDFs
  abstract class PasswordBasedKDF < KeyDerivationFunction
    # The number of iterations
    abstract def iterations : Int32
  end
end