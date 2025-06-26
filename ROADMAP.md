# crypto.cr Implementation Roadmap

This document outlines the implementation priorities for the crypto.cr library, with special focus on MTProto protocol support.

## ⚠️ Security Notice

All implementations in this library are **pure Crystal** and should be considered **experimental**. They are:
- NOT suitable for production use
- NOT protected against side-channel attacks
- NOT audited by security professionals
- Subject to potential vulnerabilities in the Crystal language itself

This roadmap is for educational and experimental purposes. Production systems should use established cryptographic libraries.

## Immediate Priority: MTProto Support

These components are essential for MTProto protocol implementation and should be implemented first:

### 1. AES-IGE Mode (Critical) ✅
- [x] AES-256-IGE encryption
- [x] AES-256-IGE decryption
- [x] Proper IGE mode chaining
- [x] Test vectors from OpenSSL and TDLib

### 2. SHA Hash Functions
- [x] SHA-256 (currently via OpenSSL)
- [ ] Native SHA-256 implementation
- [ ] SHA-1 (for legacy auth key generation)
- [ ] SHA-512 (for newer protocols)

### 3. RSA Implementation
- [ ] RSA key parsing (PEM/DER formats)
- [ ] RSA encryption with custom MTProto padding
- [ ] RSA public key fingerprint calculation
- [ ] Support for Telegram's public keys

### 4. Diffie-Hellman
- [ ] DH parameter generation
- [ ] DH key exchange implementation
- [ ] Safe prime validation (2048-bit)
- [ ] Generator validation (2, 3, 4, 5, 6, 7)

### 5. MTProto-Specific Utilities
- [ ] Message padding (12-1024 bytes)
- [ ] Auth key generation
- [ ] Message key derivation (KDF)
- [ ] AES key/IV derivation from auth key

## Secondary Priority: Core Cryptography

### Hash Functions
- [ ] Blake2b/Blake2s
- [ ] Blake3
- [ ] MD5 (legacy only)
- [ ] Keccak/SHA-3

### Password Hashing
- [ ] Argon2 (all variants)
- [ ] bcrypt
- [ ] PBKDF2

### Symmetric Encryption
- [x] **AES-IGE** (completed for MTProto)
- [x] **AES-CTR** (completed)
- [x] **AES core** (128/192/256-bit)
- [ ] AES-CBC
- [ ] AES-GCM (authenticated)
- [ ] ChaCha20
- [ ] ChaCha20-Poly1305

## Implementation Guidelines

### For Each Algorithm:
1. Create abstract base class if needed
2. Implement core algorithm
3. Add comprehensive test suite
4. Include test vectors
5. Add usage examples
6. Document security considerations

### Testing Requirements:
- Unit tests for all public methods
- Known test vectors (NIST, RFC, etc.)
- Edge cases (empty input, max size)
- Performance benchmarks
- Security property tests

### Code Structure:
```
src/crypto/
├── algorithms/
│   ├── hashes/
│   │   ├── sha256.cr
│   │   └── sha1.cr
│   ├── ciphers/
│   │   ├── aes/
│   │   │   ├── ige.cr
│   │   │   ├── cbc.cr
│   │   │   └── gcm.cr
│   │   └── chacha20.cr
│   ├── asymmetric/
│   │   ├── rsa.cr
│   │   └── dh.cr
│   └── kdf/
│       ├── pbkdf2.cr
│       └── hkdf.cr
├── protocols/
│   └── mtproto/
│       ├── padding.cr
│       ├── keys.cr
│       └── auth.cr
└── utils/
    ├── secure_random.cr
    └── constant_time.cr
```

## Timeline Estimates

### Phase 1: MTProto Essentials (4-6 weeks)
- Week 1-2: AES-IGE implementation
- Week 2-3: RSA with MTProto padding
- Week 3-4: DH implementation
- Week 4-5: MTProto utilities
- Week 5-6: Integration testing

### Phase 2: Core Algorithms (6-8 weeks)
- Week 1-2: SHA family completion
- Week 3-4: Modern hash functions
- Week 5-6: Symmetric ciphers
- Week 7-8: KDF implementations

### Phase 3: Advanced Features (8-10 weeks)
- Authenticated encryption modes
- Additional asymmetric algorithms
- Post-quantum preparations
- Performance optimizations

## Success Criteria

Each implementation must:
1. Pass all test vectors
2. Be compatible with reference implementations
3. Have clear documentation
4. Include security warnings where appropriate
5. Follow Crystal best practices
6. Be optimized for performance where possible

## Notes

- Priority is given to MTProto requirements
- Security audit recommended before production use
- Constant-time implementations for sensitive operations
- Hardware acceleration support where available