# Base classes
require "./crypto/base/*"

# Hash algorithms
require "./crypto/hashes/*"

# Key Derivation Functions
require "./crypto/kdf/*"

# Ciphers
require "./crypto/ciphers/*"

# Asymmetric algorithms
require "./crypto/asymmetric/*"

# Key Exchange algorithms
require "./crypto/key_exchange/*"

# MAC algorithms (when implemented)
# require "./crypto/mac/*"

# Protocols
require "./crypto/protocols/mtproto/rsa_utils"
require "./crypto/protocols/mtproto/dh_utils"

# Utilities (when implemented)
# require "./crypto/utils/*"

module Crypto
  # Version of the crypto library
  VERSION = "0.1.0"
  
  # Main entry point for the crypto library
end