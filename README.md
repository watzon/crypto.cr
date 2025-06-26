# crypto.cr

[![Crystal Version](https://img.shields.io/badge/crystal-%3E%3D%201.16.0-brightgreen.svg)](https://crystal-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A **pure Crystal** implementation of comprehensive cryptographic algorithms, providing a unified interface for various hashing algorithms and cryptographic primitives commonly used in cryptocurrency, security applications, protocol implementations (including MTProto), and general-purpose cryptography.

> ⚠️ **SECURITY WARNING**: This library is a pure Crystal implementation and has NOT been audited or thoroughly tested for security vulnerabilities. It should NOT be used in production systems where security is critical. Use established, audited libraries like OpenSSL for production use.

## Features

- **Pure Crystal Implementation**: All algorithms are implemented directly in Crystal without C bindings
- **Unified Interface**: All algorithms implement a common interface for easy integration
- **No External Dependencies**: Minimal reliance on external libraries (only OpenSSL for specific functions)
- **Educational Value**: Great for learning how cryptographic algorithms work
- **Extensible**: Easy to add new algorithms following the established pattern

## ⚠️ Important Security Disclaimer

This library is:
- **NOT audited** by security professionals
- **NOT suitable for production** use where security is critical
- **NOT guaranteed** to be free from implementation errors
- **NOT protected** against timing attacks or other side-channel vulnerabilities
- **Dependent on Crystal's security** - any vulnerabilities in the Crystal language itself could affect this library

### When to Use This Library
✅ Educational purposes and learning about cryptography  
✅ Prototyping and experimentation  
✅ Non-critical applications where you understand the risks  
✅ Contributing to improve Crystal's cryptographic ecosystem  

### When NOT to Use This Library
❌ Production systems handling sensitive data  
❌ Financial applications  
❌ Medical or safety-critical systems  
❌ Any application where security vulnerabilities could cause harm  
❌ Systems requiring compliance with security standards  

For production use, please use established, audited libraries like OpenSSL with proper bindings.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crypto:
    github: watzon/crypto.cr
```

Then run:
```bash
shards install
```

## Usage

### Basic Usage

```crystal
require "crypto"

# Using SCrypt for key derivation
kdf = Crypto::KDF::SCrypt.new(n: 14, r: 8, p: 1)
password = "my secure password"
salt = Random::Secure.random_bytes(16)  # 128-bit salt
derived_key = kdf.derive(password, salt, 32)  # 32-byte key
puts derived_key.hexstring

# Future hash algorithm usage (when implemented)
# hasher = Crypto::Hashes::SHA256.new
# hash = hasher.hash("my input data")
# puts hash # => hex string output
```

### SCrypt (Password Hashing)

Currently implemented algorithms:

```crystal
require "crypto"

# Using the static method for backward compatibility
password = "my_secure_password"
salt = "random_salt_value"
hash = Crypto::KDF::SCrypt.hash(
  password: password,
  salt: salt,
  n: 14,           # CPU/memory cost (2^14 iterations)
  r: 8,            # Block size
  p: 1,            # Parallelization factor
  output_length: 32 # Output length in bytes
)

puts hash.hexstring
```

### AES Encryption

```crystal
require "crypto"

# Basic AES encryption/decryption
key = Random::Secure.random_bytes(32)  # 256-bit key
plaintext = "Secret message".to_slice

# Direct block encryption (ECB mode - not recommended for most uses)
aes = Crypto::Ciphers::AES.new(key)
# Note: plaintext must be exactly 16 bytes for direct block encryption
padded = Bytes.new(16, 0)
plaintext.copy_to(padded)
ciphertext = aes.encrypt(padded)
decrypted = aes.decrypt(ciphertext)

# AES-CTR (recommended for general use)
nonce = Random::Secure.random_bytes(12)
cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
ciphertext = cipher.encrypt(plaintext)
cipher.reset  # Reset to decrypt
decrypted = cipher.decrypt(ciphertext)

# AES-IGE (for MTProto/Telegram)
iv = Random::Secure.random_bytes(32)  # 32 bytes for IGE
cipher = Crypto::Ciphers::AES_IGE.new(key, iv)
# Note: IGE requires plaintext length to be multiple of 16
padded_length = ((plaintext.size + 15) // 16) * 16
padded = Bytes.new(padded_length, 0)
plaintext.copy_to(padded)
ciphertext = cipher.encrypt(padded)
decrypted = cipher.decrypt(ciphertext)
```

### SHA Hashing

```crystal
require "crypto"

# SHA-1 (legacy compatibility)
sha1 = Crypto::Hashes::Sha1.new
hash1 = sha1.hash("Hello World")
puts hash1  # => "0a4d55a8d778e5022fab701977c5d840bbc486d0"

# SHA-256 (recommended)
sha256 = Crypto::Hashes::Sha256.new
hash256 = sha256.hash("Hello World")
puts hash256  # => "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"

# SHA-512 (highest security)
sha512 = Crypto::Hashes::Sha512.new
hash512 = sha512.hash("Hello World")
puts hash512  # => "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b"

# Binary data hashing
binary_data = Bytes[0xde, 0xad, 0xbe, 0xef]
sha256_bytes = sha256.hash_bytes(binary_data)
puts sha256_bytes.hexstring
```

### MTProto Usage

```crystal
require "crypto"

# AES-IGE encryption (now available!)
key = Random::Secure.random_bytes(32)  # 256-bit key
iv = Random::Secure.random_bytes(32)   # 2 * block size for IGE

# Important: IGE mode requires padding to 16-byte boundary
message = "Hello, Telegram!".to_slice
padded_length = ((message.size + 15) // 16) * 16
plaintext = Bytes.new(padded_length, 0)
message.copy_to(plaintext)

cipher = Crypto::Ciphers::AES_IGE.new(key, iv)
encrypted = cipher.encrypt(plaintext)
decrypted = cipher.decrypt(encrypted)

# Extract original message
original_message = String.new(decrypted[0, message.size])

# RSA with MTProto padding (when implemented)
rsa = Crypto::Asymmetric::RSA.new(public_key)
encrypted = rsa.encrypt_mtproto(data)

# DH parameter validation (when implemented)
dh = Crypto::KeyExchange::DH.new
if dh.validate_mtproto_params(p, g)
  shared_secret = dh.compute_shared_secret(public_key)
end
```

## Roadmap

### MTProto Protocol Support (Priority)

> **Note**: Even for MTProto implementations, consider using OpenSSL bindings for production. This pure Crystal implementation is primarily for educational purposes and understanding the protocol.

For MTProto implementation, the following cryptographic primitives are essential:

- [x] **Encryption**
  - [x] AES-256-IGE mode (encryption/decryption)
  - [x] AES-256-CTR mode
- [x] **Hashing**
  - [x] SHA-256 (native Crystal implementation)
  - [x] SHA-1 (for legacy compatibility)
  - [x] SHA-512
- [ ] **Key Exchange & Asymmetric**
  - [ ] RSA with custom MTProto padding
  - [ ] Diffie-Hellman with 2048-bit groups
  - [ ] DH parameter validation (safe prime checks)
- [ ] **Utilities**
  - [ ] MTProto message padding
  - [ ] MTProto key derivation functions
  - [ ] MTProto fingerprint calculation
  - [ ] Secure random number generation

### Phase 1: Core Hash Functions (Current)
- [x] **SCrypt** - Memory-hard password hashing
- [x] **SHA Family**
  - [x] SHA-1 (legacy support)
  - [x] SHA-256
  - [x] SHA-512
  - [ ] SHA-3 (Keccak winner)
- [ ] **Blake Family**
  - [ ] Blake2b
  - [ ] Blake2s
  - [ ] Blake3
- [ ] **Modern Hashes**
  - [ ] Argon2 (id, i, d variants)
  - [ ] bcrypt
  - [ ] PBKDF2

### Phase 2: Cryptocurrency & Specialized Hashes
- [ ] **X-Series** (Used in various cryptocurrencies)
  - [ ] X11
  - [ ] X13
  - [ ] X14
  - [ ] X15
  - [ ] X17
- [ ] **Mining Algorithms**
  - [ ] Ethash
  - [ ] Equihash
  - [ ] CryptoNight
  - [ ] RandomX
- [ ] **Other Crypto Hashes**
  - [ ] Groestl
  - [ ] Skein
  - [ ] JH
  - [ ] Fugue
  - [ ] Shavite3
  - [ ] NIST5
  - [ ] Qubit
  - [ ] Fresh

### Phase 3: Symmetric Cryptography
- [x] **Block Ciphers**
  - [x] AES (128, 192, 256)
  - [x] AES-IGE (Infinite Garble Extension) - *Required for MTProto*
  - [x] AES-CTR (Counter mode)
  - [ ] ChaCha20
  - [ ] Twofish
  - [ ] Serpent
- [ ] **Stream Ciphers**
  - [ ] ChaCha20
  - [ ] Salsa20
  - [ ] RC4 (legacy)
- [ ] **Authenticated Encryption**
  - [ ] AES-GCM
  - [ ] ChaCha20-Poly1305
  - [ ] AES-CCM
- [x] **MTProto Specific**
  - [x] AES-IGE encryption/decryption
  - [ ] MTProto padding schemes
  - [ ] MTProto key derivation
  - [ ] MTProto message authentication

### Phase 4: Asymmetric Cryptography
- [ ] **Key Exchange**
  - [ ] ECDH (Curve25519, secp256k1)
  - [ ] X25519
  - [ ] DH (Diffie-Hellman) - *Required for MTProto*
  - [ ] MTProto DH parameter validation
- [ ] **Digital Signatures**
  - [ ] ECDSA
  - [ ] EdDSA (Ed25519)
  - [ ] RSA signatures
  - [ ] RSA-PSS
  - [ ] Schnorr signatures
- [ ] **Public Key Encryption**
  - [ ] RSA with OAEP padding
  - [ ] RSA with PKCS#1 v1.5 padding - *Required for MTProto*
  - [ ] RSA key generation and validation
  - [ ] ElGamal

### Phase 5: Cryptographic Utilities
- [ ] **Message Authentication Codes (MAC)**
  - [ ] HMAC
  - [ ] Poly1305
  - [ ] CMAC
  - [ ] KMAC
- [ ] **Key Derivation Functions (KDF)**
  - [ ] HKDF
  - [ ] X963-KDF
  - [ ] SP800-108
- [ ] **Random Number Generation**
  - [ ] CSPRNG interface
  - [ ] Fortuna
  - [ ] DRBG implementations

### Phase 6: Advanced Features
- [ ] **Zero-Knowledge Proofs**
  - [ ] Basic ZKP primitives
  - [ ] Bulletproofs
- [ ] **Homomorphic Primitives**
  - [ ] Paillier cryptosystem
- [ ] **Post-Quantum**
  - [ ] CRYSTALS-Kyber
  - [ ] CRYSTALS-Dilithium
  - [ ] SPHINCS+
- [ ] **Threshold Cryptography**
  - [ ] Shamir's Secret Sharing
  - [ ] Threshold signatures

## Architecture

The library follows a clean, modular architecture:

```
src/crypto/
├── base/               # Abstract base classes
│   ├── hash_algorithm.cr
│   ├── cipher.cr
│   ├── asymmetric_algorithm.cr
│   ├── kdf.cr
│   └── mac.cr
├── hashes/             # Hash function implementations
│   ├── sha256.cr
│   ├── blake.cr
│   └── ...
├── kdf/                # Key derivation functions
│   ├── scrypt.cr      # ✓ Implemented
│   ├── pbkdf2.cr      # (planned)
│   └── argon2.cr      # (planned)
├── ciphers/            # Symmetric encryption (planned)
│   ├── aes/
│   │   ├── ige.cr     # MTProto priority
│   │   ├── gcm.cr
│   │   └── cbc.cr
│   └── chacha20.cr
├── asymmetric/         # Public key algorithms (planned)
│   ├── rsa.cr
│   ├── dh.cr
│   └── ecdh.cr
├── mac/                # Message authentication codes (planned)
│   ├── hmac.cr
│   └── poly1305.cr
├── protocols/          # Protocol-specific implementations
│   └── mtproto/       # MTProto-specific crypto
└── utils/              # Utility functions
```

Each category has its own namespace and base class:
- `Crypto::HashAlgorithm` for hash functions
- `Crypto::Cipher` for symmetric encryption
- `Crypto::AsymmetricAlgorithm` for public key operations
- `Crypto::KeyDerivationFunction` for KDFs
- `Crypto::MessageAuthenticationCode` for MACs

## Development

### Running Tests

```bash
crystal spec
```

### Running Benchmarks

```bash
crystal run benchmark/run.cr
```

### Adding New Algorithms

1. Create a new file in the appropriate `src/crypto/` subdirectory
2. Extend the appropriate base class from `src/crypto/base/`
3. Implement all required abstract methods
4. Add comprehensive tests in the corresponding `spec/` directory
5. Update documentation

Example for a new hash algorithm:

```crystal
require "../base/hash_algorithm"

module Crypto::Hashes
  class SHA256 < Crypto::HashAlgorithm
    def hash(input : String) : String
      hash_bytes(input.to_slice).hexstring
    end
    
    def hash_bytes(input : Bytes) : Bytes
      # Implementation here
    end
    
    def output_size : Int32
      32  # 256 bits / 8
    end
    
    def block_size : Int32
      64  # 512 bits / 8
    end
  end
end
```

Example for a new KDF:

```crystal
require "../base/kdf"

module Crypto::KDF
  class PBKDF2 < Crypto::PasswordBasedKDF
    def initialize(@iterations = 10000, @hash_function = :sha256)
    end
    
    def iterations : Int32
      @iterations
    end
    
    def derive(password : String | Bytes, salt : Bytes, output_length : Int32) : Bytes
      # Implementation here
    end
  end
end
```

## Security Considerations

### 🚨 Critical Security Notice

This is a **pure Crystal implementation** of cryptographic algorithms. This means:

1. **No Security Audit**: This code has NOT been reviewed by cryptographic experts
2. **Implementation Risks**: Pure implementations are prone to subtle bugs that can completely compromise security
3. **Side-Channel Vulnerabilities**: No protection against timing attacks, cache attacks, or other side channels
4. **Language Dependencies**: Security depends entirely on Crystal's runtime and compiler correctness
5. **No Compliance**: Does NOT meet FIPS, Common Criteria, or other security standards

### Implementation-Specific Risks

- **Timing Attacks**: Operations are not constant-time
- **Memory Safety**: Sensitive data may remain in memory after use
- **Integer Overflow**: Potential for arithmetic errors in cryptographic operations
- **Random Number Generation**: Depends on Crystal's Random::Secure
- **Compiler Optimizations**: May introduce vulnerabilities

### Best Practices (If You Must Use This)

1. **Understand the Risks**: Only use if you fully understand the security implications
2. **Non-Critical Only**: Never use for sensitive, financial, or personal data
3. **Stay Updated**: Security issues may be discovered at any time
4. **Test Thoroughly**: Verify against known test vectors
5. **Monitor Crystal Security**: Watch for Crystal language security advisories
6. **Consider Alternatives**: Use OpenSSL bindings for production systems

### Algorithms to Avoid

Even when implemented, these algorithms should NOT be used:
- **MD5**: Completely broken, collision attacks exist
- **SHA-1**: Deprecated, collision attacks demonstrated
- **DES/3DES**: Insufficient key size, deprecated
- **RC4**: Multiple vulnerabilities, deprecated

### Recommended Production Alternatives

For production use, consider:
- Crystal's OpenSSL bindings
- libsodium bindings for Crystal
- Well-audited system libraries via FFI
- Established cryptographic services

## Performance

Benchmarks on Apple M1 (coming soon):

| Algorithm | Speed (MB/s) | Memory Usage |
|-----------|-------------|--------------|
| SCrypt    | TBD         | TBD          |
| SHA-256   | TBD         | TBD          |
| Blake2b   | TBD         | TBD          |

## Contributing

1. Fork it (https://github.com/watzon/crypto.cr/fork)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`crystal spec`)
5. Format your code (`crystal tool format`)
6. Commit your changes (`git commit -am 'Add some feature'`)
7. Push to the branch (`git push origin my-new-feature`)
8. Create a new Pull Request

### Contribution Ideas

- Implement missing algorithms
- Optimize existing implementations
- Add hardware acceleration support
- Improve documentation
- Add more test vectors
- Create benchmarking suite

## References

- [NIST Cryptographic Standards](https://csrc.nist.gov/publications/sp)
- [RFC 7914 - SCrypt](https://tools.ietf.org/html/rfc7914)
- [MTProto Mobile Protocol](https://core.telegram.org/mtproto)
- [MTProto Detailed Description](https://core.telegram.org/mtproto/description)
- [Telegram API TL-schema](https://core.telegram.org/schema)
- [Cryptocurrency Mining Algorithms](https://en.bitcoin.it/wiki/List_of_alternative_cryptocurrencies)
- [SUPERCOP Crypto Benchmarks](https://bench.cr.yp.to/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributors

- [watzon](https://github.com/watzon) Chris Watson - creator, maintainer

## Acknowledgments

- Crystal standard library for OpenSSL bindings
- The broader Crystal community for tooling and support
- Original algorithm authors and cryptography researchers