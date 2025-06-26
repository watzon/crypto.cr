module Crypto
  module MAC
  end
  
  # Abstract base class for Message Authentication Codes
  abstract class MessageAuthenticationCode
    # Computes the MAC for the given data
    abstract def compute(data : Bytes, key : Bytes) : Bytes
    
    # Verifies a MAC
    def verify(data : Bytes, key : Bytes, mac : Bytes) : Bool
      computed = compute(data, key)
      return false if computed.size != mac.size
      
      # Constant-time comparison
      result = 0_u8
      computed.size.times do |i|
        result |= computed[i] ^ mac[i]
      end
      result == 0
    end
    
    # Returns the output size in bytes
    abstract def output_size : Int32
  end
end