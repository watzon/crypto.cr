# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive README with detailed roadmap for a fully featured crypto library
- CHANGELOG.md for tracking version history
- ROADMAP.md with implementation priorities focusing on MTProto support
- SECURITY.md with comprehensive security warnings and guidelines
- Placeholder implementations for 19 hash algorithms with proper error handling
- Instance method for SCrypt to satisfy abstract interface requirements
- Support for Crystal >= 1.16.0
- MTProto-specific requirements and examples in documentation
- Example file demonstrating SCrypt usage (examples/scrypt_example.cr)
- Strong security warnings emphasizing this is a pure Crystal implementation
- Clear guidance on when to use and when NOT to use this library
- **AES block cipher implementation** (128/192/256-bit keys)
  - Pure Crystal implementation with NIST-compliant algorithm
  - Optimized to use Bytes/slices instead of arrays for performance
  - Full key expansion, SubBytes, ShiftRows, MixColumns transformations
  - Comprehensive tests with NIST FIPS 197 test vectors
- **AES-CTR mode** (Counter mode for stream cipher operation)
  - Supports random access via seek() method
  - Handles arbitrary length data (not limited to block sizes)
  - NIST SP 800-38A compliant with test vectors
- **AES-IGE mode** (Infinite Garble Extension for MTProto)
  - Required for Telegram/MTProto protocol implementation
  - Forward error propagation as per specification
  - Compatible with OpenSSL's IGE implementation
  - Verified against OpenSSL test vectors and TDLib compatibility tests

### Changed
- Updated Crystal version requirement from 0.24.1 to >= 1.16.0
- Modernized SCrypt implementation to use SHA-256 instead of SHA-1 for PBKDF2
- Fixed integer division to use `//` operator for Crystal 1.16.3 compatibility
- Fixed arithmetic overflow using wrapping addition (`&+`)
- Updated test expectations to match SHA-256 output
- Restructured README with phases for systematic development
- Enhanced CLAUDE.md with expanded project vision
- **Major reorganization**: Moved from flat `algorithms/` directory to categorized structure:
  - Hash algorithms now in `src/crypto/hashes/`
  - KDF algorithms now in `src/crypto/kdf/`
  - Base classes in `src/crypto/base/`
  - Specs mirror source structure
- Updated module namespaces (e.g., `Crypto::Algorithms::SCrypt` → `Crypto::KDF::SCrypt`)
- SCrypt now implements proper KDF interface with `derive` method

### Fixed
- Abstract method implementation errors in all algorithm classes
- Integer division type errors in SCrypt implementation
- Arithmetic overflow in Salsa20/8 implementation
- Build errors with Crystal 1.16.3

## [0.1.0] - 2017-03-25

### Added
- Initial project structure
- SCrypt algorithm implementation
- Basic test suite for SCrypt
- Abstract HashAlgorithm base class
- Placeholder files for future algorithms