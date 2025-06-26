require "../src/crypto"

# Example 1: Using SCrypt as a KDF
puts "Example 1: Key Derivation Function interface"
scrypt = Crypto::KDF::SCrypt.new(n: 14, r: 8, p: 1)
password = "my password"
salt = Random::Secure.random_bytes(16) # 128-bit salt
derived_key = scrypt.derive(password, salt, 32) # 256-bit key
puts "Derived key: #{derived_key.hexstring}"
puts "Key length: #{derived_key.size} bytes"
puts

# Example 2: SCrypt with custom parameters
puts "Example 2: Custom parameters"
password = "super_secret_password"
salt = "random_salt_123"

# Parameters explained:
# n: CPU/memory cost parameter (N = 2^n iterations)
# r: Block size parameter (affects memory and CPU usage)
# p: Parallelization parameter (affects memory usage)
# output_length: Desired hash output length in bytes

hash = Crypto::KDF::SCrypt.hash(
  password: password,
  salt: salt,
  n: 14,            # 2^14 = 16384 iterations (recommended minimum)
  r: 8,             # Block size (typical value)
  p: 1,             # Parallelization (1 for sequential)
  output_length: 32 # 256-bit output
)

puts "Password: #{password}"
puts "Salt: #{salt}"
puts "Hash (hex): #{hash.hexstring}"
puts "Hash length: #{hash.size} bytes"
puts

# Example 3: Different cost parameters for different use cases
puts "Example 3: Different security levels"

# Low security (fast) - for testing only
low_security = Crypto::KDF::SCrypt.hash(password, salt, n: 10, r: 8, p: 1, output_length: 32)
puts "Low security (n=10): #{low_security.hexstring[0..16]}..."

# Medium security - reasonable for most applications
medium_security = Crypto::KDF::SCrypt.hash(password, salt, n: 14, r: 8, p: 1, output_length: 32)
puts "Medium security (n=14): #{medium_security.hexstring[0..16]}..."

# High security - for sensitive data
high_security = Crypto::KDF::SCrypt.hash(password, salt, n: 16, r: 8, p: 1, output_length: 32)
puts "High security (n=16): #{high_security.hexstring[0..16]}..."

puts
puts "Note: Higher 'n' values increase computation time exponentially"