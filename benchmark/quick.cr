require "benchmark"
require "openssl"
require "../src/crypto"

puts "🔐 crypto.cr Quick Benchmark"
puts "=" * 50

# Test data
data_1kb = Bytes.new(1024) { |i| (i % 256).to_u8 }
iterations = 1000

puts "\n📊 Hash Function Performance (1KB, #{iterations} iterations)"
puts "-" * 50

# SHA-256
puts "\nSHA-256:"
crystal_sha256 = Crypto::Hashes::Sha256.new
crystal_time = Benchmark.measure do
  iterations.times { crystal_sha256.hash_bytes(data_1kb) }
end
crystal_ops = iterations.to_f / crystal_time.real
crystal_mb = (1024 * crystal_ops) / (1024 * 1024)

openssl_time = Benchmark.measure do
  iterations.times do
    OpenSSL::Digest.new("SHA256").update(data_1kb).final
  end
end
openssl_ops = iterations.to_f / openssl_time.real
openssl_mb = (1024 * openssl_ops) / (1024 * 1024)

puts "  Crystal: #{crystal_mb.round(2)} MB/s"
puts "  OpenSSL: #{openssl_mb.round(2)} MB/s"
puts "  Ratio: #{(openssl_ops / crystal_ops).round(2)}x faster"

# SHA-1
puts "\nSHA-1:"
crystal_sha1 = Crypto::Hashes::Sha1.new
crystal_time = Benchmark.measure do
  iterations.times { crystal_sha1.hash_bytes(data_1kb) }
end
crystal_ops = iterations.to_f / crystal_time.real
crystal_mb = (1024 * crystal_ops) / (1024 * 1024)

openssl_time = Benchmark.measure do
  iterations.times do
    OpenSSL::Digest.new("SHA1").update(data_1kb).final
  end
end
openssl_ops = iterations.to_f / openssl_time.real
openssl_mb = (1024 * openssl_ops) / (1024 * 1024)

puts "  Crystal: #{crystal_mb.round(2)} MB/s"
puts "  OpenSSL: #{openssl_mb.round(2)} MB/s"
puts "  Ratio: #{(openssl_ops / crystal_ops).round(2)}x faster"

puts "\n🔒 AES-256-CTR Performance (1KB, #{iterations} iterations)"
puts "-" * 50

key = Random::Secure.random_bytes(32)
nonce = Random::Secure.random_bytes(12)
iv = Random::Secure.random_bytes(16)

# Crystal AES-CTR
crystal_time = Benchmark.measure do
  iterations.times do
    cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
    cipher.encrypt(data_1kb)
  end
end
crystal_ops = iterations.to_f / crystal_time.real
crystal_mb = (1024 * crystal_ops) / (1024 * 1024)

# OpenSSL AES-CTR
openssl_time = Benchmark.measure do
  iterations.times do
    cipher = OpenSSL::Cipher.new("AES-256-CTR")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    cipher.update(data_1kb) + cipher.final
  end
end
openssl_ops = iterations.to_f / openssl_time.real
openssl_mb = (1024 * openssl_ops) / (1024 * 1024)

puts "  Crystal: #{crystal_mb.round(2)} MB/s"
puts "  OpenSSL: #{openssl_mb.round(2)} MB/s"
puts "  Ratio: #{(openssl_ops / crystal_ops).round(2)}x faster"

puts "\n" + "=" * 50
puts "✅ Quick benchmark complete!"
puts "Note: Pure Crystal implementations are for educational use."
puts "Use OpenSSL bindings for production systems."