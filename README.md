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

# Hash algorithms
hasher = Crypto::Hashes::SHA3_256.new
hash = hasher.hash("my input data")
puts hash # => hex string output

# SHAKE extendable output functions
shake = Crypto::Hashes::SHAKE256.new
output = shake.shake("input data", 64)  # 64 bytes output
puts output.hexstring
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

### SHA-3 and SHAKE

```crystal
require "crypto"

# SHA3-256
sha3_256 = Crypto::Hashes::SHA3_256.new
hash = sha3_256.hash("Hello World")
puts hash  # => "e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51"

# SHA3-512 
sha3_512 = Crypto::Hashes::SHA3_512.new
hash = sha3_512.hash("Hello World")
puts hash  # => "3b62be6485a61c7a35dd3fef8ae32c61b44eddc58bc9ae3f0c62ac1e88354c14e80174e2d058e8c5c4cecc95ac228cd4cbf2e3f90b4ecf3a653ad7f2c6076ab8"

# SHAKE128 - variable length output
shake128 = Crypto::Hashes::SHAKE128.new
output = shake128.shake("Hello", 32)  # 32 bytes output
puts output.hexstring

# SHAKE256 - for longer outputs
shake256 = Crypto::Hashes::SHAKE256.new
output = shake256.shake("Hello", 64)  # 64 bytes output
puts output.hexstring
```

### RSA Encryption/Decryption

```crystal
require "crypto"

# Use Telegram's public key for MTProto (via MTProto utilities)
telegram_keys = Crypto::Protocols::MTProto::RSAUtils.get_all_telegram_keys
telegram_rsa = telegram_keys.values.first
puts telegram_rsa.fingerprint_hex  # Shows key fingerprint

# Encrypt data with PKCS#1 v1.5 padding (MTProto compatible)
message = "Secret message"
encrypted = telegram_rsa.encrypt(message.to_slice)
# Note: Decryption requires private key (not available for Telegram's key)

# Create custom RSA key (for testing/other purposes)
# These are example values - use proper key generation in practice
n = BigInt.new("123456789...")  # Modulus
e = BigInt.new("65537")         # Public exponent
d = BigInt.new("987654321...")  # Private exponent (for decryption)
custom_rsa = Crypto::Asymmetric::RSA.new(n, e, d)

# Encrypt and decrypt
plaintext = "Hello RSA!".to_slice
ciphertext = custom_rsa.encrypt(plaintext)
decrypted = custom_rsa.decrypt(ciphertext)
puts String.new(decrypted)  # => "Hello RSA!"

# Get key fingerprint for MTProto protocol
fingerprint = custom_rsa.fingerprint_int
puts "Fingerprint: #{fingerprint}"

# Export public key in PEM format
pem_key = custom_rsa.to_pem
puts pem_key
```

### Diffie-Hellman Key Exchange

```crystal
require "crypto"

# Create DH parameters (prime p and generator g)
p = BigInt.new("your_prime_here")
g = BigInt.new("2")
dh_params = Crypto::DH::DHParameters.new(p, g)

# Generate keypairs for Alice and Bob
alice_dh = Crypto::DH::DiffieHellman.new(dh_params)
alice_private, alice_public = alice_dh.generate_keypair

bob_dh = Crypto::DH::DiffieHellman.new(dh_params)
bob_private, bob_public = bob_dh.generate_keypair

# Compute shared secrets (should be identical)
shared_secret_alice = alice_private.compute_shared_secret(bob_public)
shared_secret_bob = bob_private.compute_shared_secret(alice_public)
puts shared_secret_alice == shared_secret_bob  # => true

# MTProto-specific DH (recommended for Telegram protocols)
# Uses Telegram's official 2048-bit safe prime
dh_params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters(2)
alice_keypair = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair(2)
bob_keypair = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair(2)

# Convert public keys to MTProto byte format (256 bytes)
alice_public_bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(alice_keypair[:public])
bob_public_bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(bob_keypair[:public])

# Parse public keys from bytes
alice_public_parsed = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(alice_public_bytes)
bob_public_parsed = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(bob_public_bytes)

# Compute shared secrets
shared_secret = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(
  alice_keypair[:private], 
  bob_public_parsed
)
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

# RSA with MTProto padding (now available!)
keys = Crypto::Protocols::MTProto::RSAUtils.get_all_telegram_keys
rsa = keys.values.first
encrypted = rsa.encrypt(data)  # Uses PKCS#1 v1.5 padding
fingerprint = rsa.fingerprint_int  # For MTProto protocol

# DH key exchange (now available!)
dh_params = Crypto::Protocols::MTProto::DHUtils.create_mtproto_parameters(2)
alice_keypair = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair(2)
bob_keypair = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair(2)

# Exchange public keys and compute shared secret
shared_secret_alice = alice_keypair[:private].compute_shared_secret(bob_keypair[:public])
shared_secret_bob = bob_keypair[:private].compute_shared_secret(alice_keypair[:public])
# shared_secret_alice == shared_secret_bob
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
- [x] **Key Exchange & Asymmetric**
  - [x] RSA with PKCS#1 v1.5 padding (MTProto compatible)
  - [x] RSA public key fingerprint calculation
  - [x] Telegram public key support
  - [x] Diffie-Hellman with 2048-bit groups
  - [x] DH parameter validation (safe prime checks)
  - [x] MTProto DH implementation with Telegram's parameters
- [x] **MTProto Utilities**
  - [x] RSA utilities with Telegram public keys
  - [x] DH utilities with MTProto parameters
  - [x] Fingerprint calculation and validation
  - [x] Key format conversion helpers
  - [ ] MTProto message padding
  - [ ] MTProto key derivation functions
  - [ ] Secure random number generation

### Phase 1: Core Hash Functions (Current)
- [x] **SCrypt** - Memory-hard password hashing
- [x] **SHA Family**
  - [x] SHA-1 (legacy support)
  - [x] SHA-256
  - [x] SHA-512
  - [x] SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
  - [x] SHAKE (SHAKE128, SHAKE256 - extendable output functions)
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
- [x] **Key Exchange**
  - [x] DH (Diffie-Hellman) - *Required for MTProto*
  - [x] MTProto DH parameter validation
  - [x] Safe prime validation and generator verification
  - [x] MTProto byte format conversion
  - [x] MTProto utilities and helpers
  - [ ] ECDH (Curve25519, secp256k1)
  - [ ] X25519
- [ ] **Digital Signatures**
  - [ ] ECDSA
  - [ ] EdDSA (Ed25519)
  - [ ] RSA signatures
  - [ ] RSA-PSS
  - [ ] Schnorr signatures
- [x] **Public Key Encryption**
  - [x] RSA with PKCS#1 v1.5 padding - *Required for MTProto*
  - [x] RSA key parsing (PEM/DER formats)
  - [x] RSA fingerprint calculation for MTProto
  - [x] Telegram public key integration
  - [x] MTProto RSA utilities and helpers
  - [ ] RSA with OAEP padding
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
# Quick benchmark (recommended)
crystal run benchmark/quick.cr --release

# Comprehensive benchmark suite
crystal run benchmark/run.cr --release
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

### Benchmark Results (Crystal vs OpenSSL)

Performance comparison on Apple M1 with Crystal 1.16.0 (release mode):

| Algorithm | Crystal (MB/s) | OpenSSL (MB/s) | OpenSSL Advantage |
|-----------|---------------|----------------|-------------------|
| SHA-1     | 56.6          | 1192.6         | 21.1x faster      |
| SHA-256   | 54.5          | 215.2          | 3.9x faster       |
| AES-256-CTR | 51.2        | 730.4          | 14.3x faster      |

### Running Benchmarks

```bash
# Quick benchmark (recommended)
crystal run benchmark/quick.cr --release

# Simple benchmark with detailed output
crystal run benchmark/simple.cr --release

# Full comprehensive benchmark suite
crystal run benchmark/run.cr --release
```

### Performance Notes

- **Pure Crystal implementations** are 4-21x slower than OpenSSL (as expected)
- **Educational/experimental use**: Perfect for learning cryptographic algorithms
- **Production systems**: Use OpenSSL bindings for performance and security
- **Memory usage**: Pure Crystal implementations use more memory due to GC overhead
- **Constant-time**: OpenSSL implementations have better protection against timing attacks

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