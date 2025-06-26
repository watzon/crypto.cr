# Security Policy

## 🚨 CRITICAL WARNING

**This library is NOT suitable for production use where security matters.**

crypto.cr is a **pure Crystal implementation** of cryptographic algorithms intended for:
- Educational purposes
- Understanding how cryptographic algorithms work
- Prototyping and experimentation
- Contributing to Crystal's ecosystem

## Why This Library Is NOT Secure

### 1. No Security Audit
- This code has never been reviewed by cryptographic experts
- No formal verification has been performed
- No penetration testing has been conducted

### 2. Implementation Vulnerabilities
Pure language implementations of cryptographic algorithms are extremely difficult to get right:
- **Timing attacks**: Operations are not constant-time
- **Cache attacks**: No protection against cache-based side channels  
- **Power analysis**: No protection against power-based side channels
- **Fault attacks**: No protection against induced faults
- **Memory attacks**: Sensitive data may remain in memory

### 3. Language-Level Dependencies
This library's security is entirely dependent on Crystal's:
- Memory management (GC behavior)
- Integer arithmetic implementation
- Compiler optimizations
- Runtime behavior
- Standard library security

Any vulnerability in Crystal itself directly affects this library.

### 4. Missing Security Features
- No secure memory wiping
- No constant-time operations
- No protection against compiler optimizations
- No hardware security module support
- No FIPS compliance
- No Common Criteria certification

## Known Vulnerable Algorithms

Even when properly implemented, these algorithms are broken and included only for compatibility:
- **MD5**: Collision attacks, should never be used
- **SHA-1**: Collision attacks demonstrated, deprecated
- **DES/3DES**: Key size too small, deprecated
- **RC4**: Multiple vulnerabilities, completely broken

## When You Can Use This Library

✅ **Educational Projects**: Learning about cryptography  
✅ **Toy Projects**: Non-sensitive personal experiments  
✅ **Research**: Understanding algorithm internals  
✅ **Development**: Prototyping before moving to production libraries  

## When You MUST NOT Use This Library

❌ **Production Systems**: Any system handling real user data  
❌ **Financial Applications**: Banking, cryptocurrency wallets, payment systems  
❌ **Healthcare**: Medical records, patient data  
❌ **Government**: Any government or military applications  
❌ **Personal Data**: Systems handling PII, passwords, or private keys  
❌ **Commercial Products**: Any software sold or distributed to others  
❌ **Legal Compliance**: Systems requiring regulatory compliance  

## Recommended Alternatives

For production use, please use:

### Crystal Bindings
- [OpenSSL bindings](https://crystal-lang.org/api/OpenSSL.html) (built into Crystal)
- [Libsodium bindings](https://github.com/didactic-drunk/sodium.cr)
- System cryptographic libraries via FFI

### External Services
- Hardware Security Modules (HSMs)
- Key Management Services (AWS KMS, Azure Key Vault, etc.)
- Established cryptographic libraries in other languages

## Reporting Security Issues

While this library is not intended for production use, we still want to know about security issues.

### For Implementation Bugs
- Open a public issue describing the problem
- Include proof of concept if possible
- Suggest fixes if you have them

### For Design Issues  
- Open a discussion about the design flaw
- Propose alternative approaches
- Reference relevant papers or standards

### For Crystal Language Issues
- Report to the Crystal team directly
- Reference how it affects this library
- Consider submitting patches upstream

## Security Checklist for Contributors

If you contribute to this library:

- [ ] Understand this is for education, not production
- [ ] Add clear warnings to any new algorithms
- [ ] Include test vectors from reputable sources
- [ ] Document any known limitations
- [ ] Never claim an implementation is "secure"
- [ ] Reference the original papers/standards
- [ ] Add timing attack warnings where relevant

## Future Security Improvements

While this library will never be suitable for high-security applications, potential improvements include:

1. **Constant-time operations** where possible in Crystal
2. **Memory wiping** utilities (limited by GC)
3. **Better test coverage** with known vectors
4. **Formal verification** of algorithm logic
5. **Side-channel analysis** documentation

## Final Warning

**If security matters for your use case, DO NOT use this library.**

Use established, audited, production-ready cryptographic libraries instead. The cost of a cryptographic failure far exceeds any benefit from using a pure Crystal implementation.

Remember: **Cryptography is hard. Don't roll your own crypto.**