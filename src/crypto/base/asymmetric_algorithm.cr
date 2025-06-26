module Crypto
  module Asymmetric
  end
  
  # Abstract base class for asymmetric (public key) algorithms
  abstract class AsymmetricAlgorithm
    # Returns the public key
    abstract def public_key : Bytes
    
    # Returns the key size in bits
    abstract def key_size : Int32
  end
  
  # Abstract base class for encryption algorithms
  abstract class AsymmetricEncryption < AsymmetricAlgorithm
    # Encrypts data with the public key
    abstract def encrypt(data : Bytes) : Bytes
    
    # Decrypts data with the private key
    abstract def decrypt(data : Bytes) : Bytes
  end
  
  # Abstract base class for signature algorithms
  abstract class SignatureAlgorithm < AsymmetricAlgorithm
    # Signs data with the private key
    abstract def sign(data : Bytes) : Bytes
    
    # Verifies a signature with the public key
    abstract def verify(data : Bytes, signature : Bytes) : Bool
  end
  
  # Abstract base class for key exchange algorithms
  abstract class KeyExchange < AsymmetricAlgorithm
    # Generates a shared secret from a public key
    abstract def compute_shared_secret(public_key : Bytes) : Bytes
  end
end