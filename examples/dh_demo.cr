require "../src/crypto"

# Example demonstrating Diffie-Hellman key exchange for MTProto
puts "=== MTProto Diffie-Hellman Key Exchange Demo ==="
puts ""

# Create MTProto DH parameters (using Telegram's 2048-bit safe prime)
puts "1. Creating MTProto DH parameters..."
puts "   - Prime: 2048-bit safe prime used by Telegram"
puts "   - Generator: 2 (default)"

# Client (Alice) generates a keypair
puts ""
puts "2. Client (Alice) generates DH keypair..."
alice_private, alice_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
puts "   - Private key: #{alice_private.x.to_s(16)[0..20]}... (#{alice_private.x.bit_length} bits)"
puts "   - Public key:  #{alice_public.y.to_s(16)[0..20]}... (#{alice_public.y.bit_length} bits)"

# Server (Bob) generates a keypair  
puts ""
puts "3. Server (Bob) generates DH keypair..."
bob_private, bob_public = Crypto::Protocols::MTProto::DHUtils.generate_mtproto_keypair
puts "   - Private key: #{bob_private.x.to_s(16)[0..20]}... (#{bob_private.x.bit_length} bits)"
puts "   - Public key:  #{bob_public.y.to_s(16)[0..20]}... (#{bob_public.y.bit_length} bits)"

# Convert public keys to MTProto byte format (for network transmission)
puts ""
puts "4. Converting public keys to MTProto format (256 bytes each)..."
alice_public_bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(alice_public)
bob_public_bytes = Crypto::Protocols::MTProto::DHUtils.public_key_to_mtproto_bytes(bob_public)
puts "   - Alice's public key: #{alice_public_bytes.size} bytes"
puts "   - Bob's public key:   #{bob_public_bytes.size} bytes"

# Simulate network exchange - each party receives the other's public key
puts ""
puts "5. Simulating network exchange of public keys..."
alice_received_bob_key = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(bob_public_bytes)
bob_received_alice_key = Crypto::Protocols::MTProto::DHUtils.public_key_from_mtproto_bytes(alice_public_bytes)
puts "   - Keys exchanged successfully"

# Compute shared secrets
puts ""
puts "6. Computing shared secrets..."
alice_shared = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(alice_private, alice_received_bob_key)
bob_shared = Crypto::Protocols::MTProto::DHUtils.compute_mtproto_shared_secret(bob_private, bob_received_alice_key)

puts "   - Alice's shared secret: #{alice_shared.hexstring[0..20]}... (#{alice_shared.size} bytes)"
puts "   - Bob's shared secret:   #{bob_shared.hexstring[0..20]}... (#{bob_shared.size} bytes)"

# Verify they match
puts ""
puts "7. Verifying shared secrets match..."
if alice_shared == bob_shared
  puts "   ✓ SUCCESS: Shared secrets match!"
  puts "   ✓ Secure key exchange completed"
else
  puts "   ✗ ERROR: Shared secrets don't match!"
end

puts ""
puts "=== Demo completed ==="
puts ""
puts "Security features implemented:"
puts "• 2048-bit safe prime (Telegram's official DH prime)"
puts "• Generator validation (2, 5, 6 are valid for this prime)"
puts "• Public key range validation"
puts "• Private key range validation for safe primes"
puts "• Secure random private key generation"
puts "• Protection against small subgroup attacks"
puts "• MTProto-compatible byte format (256 bytes for 2048-bit keys)"