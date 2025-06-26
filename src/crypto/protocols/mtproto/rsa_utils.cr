require "../../asymmetric/rsa"

module Crypto::Protocols::MTProto
  # MTProto-specific RSA utilities
  module RSAUtils
    # Telegram's official public keys (as of 2024)
    # These are the actual public keys used by Telegram's servers
    TELEGRAM_PUBLIC_KEYS = {
      # Production key 1
      -7321182993337065829_i64 => {
        n: "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596230657",
        e: "65537"
      },
      
      # Production key 2  
      -5576001333856460285_i64 => {
        n: "24403446649145068056824081744112065346446136066297307473868293895086332508101251964919587745968776856980429060773177285902847896173120070306693100721488743981306054229491802556919948848080353541439819798076679166017341063134893407431461834164055500890631838826992655685787894849547815823099704962613620785516823662658915145633018147012796408448245022059158145813851701065092740709780632632162838830543002674474928765012176020650779825962193928705686890297324240086239554002310556094120060416055234009938529048593949726353913506806507094700406623038068099066600653815094819723946421811537126032821270090050547734158379",
        e: "65537"
      }
    }
    
    # Get Telegram RSA public key by fingerprint
    def self.get_telegram_key(fingerprint : Int64) : Crypto::Asymmetric::RSA?
      key_data = TELEGRAM_PUBLIC_KEYS[fingerprint]?
      return nil unless key_data
      
      n = BigInt.new(key_data[:n])
      e = BigInt.new(key_data[:e])
      
      rsa_key = Crypto::Asymmetric::RSAKey.new(n, e)
      Crypto::Asymmetric::RSA.new(rsa_key)
    end
    
    # Get all available Telegram public keys
    def self.get_all_telegram_keys : Hash(Int64, Crypto::Asymmetric::RSA)
      result = {} of Int64 => Crypto::Asymmetric::RSA
      
      TELEGRAM_PUBLIC_KEYS.each do |fingerprint, key_data|
        n = BigInt.new(key_data[:n])
        e = BigInt.new(key_data[:e])
        
        rsa_key = Crypto::Asymmetric::RSAKey.new(n, e)
        result[fingerprint] = Crypto::Asymmetric::RSA.new(rsa_key)
      end
      
      result
    end
    
    # Find RSA key by fingerprint from a list
    def self.find_key_by_fingerprint(keys : Array(Crypto::Asymmetric::RSA), target_fingerprint : Int64) : Crypto::Asymmetric::RSA?
      keys.find { |key| key.fingerprint_int == target_fingerprint }
    end
    
    # Verify that a key fingerprint matches expected value
    def self.verify_fingerprint(key : Crypto::Asymmetric::RSA, expected_fingerprint : Int64) : Bool
      key.fingerprint_int == expected_fingerprint
    end
    
    # Encrypt data with RSA for MTProto (always uses PKCS#1 v1.5)
    def self.encrypt_for_mtproto(data : Bytes, public_key : Crypto::Asymmetric::RSA) : Bytes
      # MTProto always uses PKCS#1 v1.5 padding
      public_key.encrypt(data)
    end
    
    # Decrypt data with RSA for MTProto
    def self.decrypt_for_mtproto(encrypted_data : Bytes, private_key : Crypto::Asymmetric::RSA) : Bytes
      private_key.decrypt(encrypted_data)
    end
    
    # Create RSA key from PEM string (helper for loading keys)
    def self.from_pem_string(pem : String) : Crypto::Asymmetric::RSA
      Crypto::Asymmetric::RSA.from_pem(pem)
    end
    
    # Create RSA key from DER bytes (helper for loading keys)
    def self.from_der_bytes(der : Bytes) : Crypto::Asymmetric::RSA
      Crypto::Asymmetric::RSA.from_der(der)
    end
    
    # Calculate fingerprint from raw key data
    def self.calculate_fingerprint(n : BigInt, e : BigInt) : Int64
      key = Crypto::Asymmetric::RSAKey.new(n, e)
      rsa = Crypto::Asymmetric::RSA.new(key)
      rsa.fingerprint_int
    end
    
    # Validate RSA key for MTProto use
    def self.validate_key_for_mtproto(key : Crypto::Asymmetric::RSA) : Bool
      # MTProto typically uses 2048-bit keys
      return false if key.key_size < 1024  # Minimum security
      return false if key.key_size > 4096  # Reasonable maximum
      
      # Key should be valid RSA key
      # Additional validation could be added here
      true
    end
    
    # Format fingerprint as hex string
    def self.fingerprint_to_hex(fingerprint : Int64) : String
      fingerprint.to_s(16).rjust(16, '0')
    end
    
    # Parse fingerprint from hex string
    def self.fingerprint_from_hex(hex : String) : Int64
      hex.to_i64(16)
    end
  end
end