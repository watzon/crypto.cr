# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

crypto.cr is a comprehensive cryptographic library for Crystal, aiming to provide a unified interface for various cryptographic primitives including hashing algorithms, symmetric/asymmetric encryption, digital signatures, and more. It's designed for use in cryptocurrency applications, security tools, and general-purpose cryptography.

## Key Architecture

The codebase follows a modular, object-oriented design:

1. **Abstract Base Classes**: 
   - `HashAlgorithm` (src/crypto/hash-algorithm.cr) - For all hash functions
   - `Cipher` (to be created) - For symmetric encryption algorithms
   - `AsymmetricAlgorithm` (to be created) - For public key operations
   - `KDF` (to be created) - For key derivation functions

2. **Current Structure**: src/crypto/algorithms/
   - Currently only SCrypt is fully implemented
   - 19 placeholder files exist for various hash algorithms
   - Each algorithm is self-contained in its own file

3. **Current Structure**:
   ```
   src/crypto/
   ├── base/               # Abstract base classes
   │   ├── hash_algorithm.cr
   │   ├── cipher.cr
   │   ├── asymmetric_algorithm.cr
   │   ├── kdf.cr
   │   └── mac.cr
   ├── hashes/             # Hash functions (SHA, Blake, etc.)
   ├── ciphers/            # Symmetric ciphers (AES, ChaCha20, etc.)
   ├── asymmetric/         # Public key algorithms (RSA, ECC, etc.)
   ├── kdf/                # Key derivation functions (SCrypt, PBKDF2, etc.)
   ├── mac/                # Message authentication codes (HMAC, etc.)
   ├── protocols/          # Higher-level protocols
   │   └── mtproto/       # MTProto specific implementations
   └── utils/              # Utility functions
   ```

4. **Module Structure**:
   - Main module: `Crypto`
   - Hash algorithms: `Crypto::Hashes::<Algorithm>`
   - KDF algorithms: `Crypto::KDF::<Algorithm>`
   - Ciphers: `Crypto::Ciphers::<Algorithm>` (future)
   - Asymmetric: `Crypto::Asymmetric::<Algorithm>` (future)
   - MAC: `Crypto::MAC::<Algorithm>` (future)

## Development Commands

```bash
# Install dependencies
shards install

# Run all tests
crystal spec

# Run specific test file
crystal spec spec/crypto_spec.cr

# Format code
crystal tool format

# Build the library
crystal build src/crypto.cr

# Check for unreachable code
crystal tool unreachable
```

## Adding New Algorithms

### Hash Algorithm:
1. Create a new file in `src/crypto/hashes/` (e.g., `blake2b.cr`)
2. Add `require "../base/hash_algorithm"`
3. Define a class in `Crypto::Hashes` that extends `Crypto::HashAlgorithm`
4. Implement all abstract methods: `hash`, `hash_bytes`, `output_size`, `block_size`
5. Add tests in `spec/hashes/`

Example:
```crystal
require "../base/hash_algorithm"

module Crypto::Hashes
  class Blake2b < Crypto::HashAlgorithm
    def hash(input : String) : String
      hash_bytes(input.to_slice).hexstring
    end
    
    def hash_bytes(input : Bytes) : Bytes
      # Implementation here
    end
    
    def output_size : Int32
      64 # 512 bits
    end
    
    def block_size : Int32
      128 # 1024 bits
    end
  end
end
```

### KDF Algorithm:
1. Create in `src/crypto/kdf/`
2. Extend `Crypto::PasswordBasedKDF` or `Crypto::KeyDerivationFunction`
3. Implement `derive` and `iterations` (if password-based)
4. Add tests in `spec/kdf/`

## Testing Guidelines

- Use Crystal's built-in spec framework
- Test each algorithm against known test vectors
- Include edge cases (empty strings, very long inputs)
- Follow the pattern established in the SCrypt tests

## Code Style

- Use 2-space indentation (enforced by .editorconfig)
- UTF-8 encoding, LF line endings
- Run `crystal tool format` before committing
- Keep algorithm implementations self-contained

## Current Implementation Status

- **Hash Functions**: SHA-1, SHA-256, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, CRC32
- **KDF**: SCrypt (fully functional with tests)
- **Ciphers**: AES (128/192/256-bit), AES-CTR, AES-IGE
- **Asymmetric**: RSA with PKCS#1 v1.5 padding, Diffie-Hellman key exchange
- **Protocols**: MTProto utilities for RSA and DH operations
- **Planned**: Blake, Fresh, Fugue, Groestl, Keccak, NIST5, Qubit, SHA1, SHA256, Shavite3, Skein, X11-X17, and others
- **Note**: Remove the test code in src/crypto.cr before release

## Important Notes

- The project is in early development (v0.1.0)
- Crystal version in shard.yml (0.24.1) should be updated to match current standards
- When implementing algorithms, ensure they're compatible with their reference implementations
- Consider adding CI/CD pipeline for automated testing