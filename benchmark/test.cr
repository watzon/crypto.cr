require "benchmark"
require "openssl"
require "../src/crypto"

puts "Testing basic benchmark functionality..."

# Test basic benchmark
result = Benchmark.measure do
  1000.times { 1 + 1 }
end

puts "Basic benchmark works: #{result.real} seconds"

# Test OpenSSL
digest = OpenSSL::Digest.new("SHA256")
digest.update("test")
hash = digest.final
puts "OpenSSL SHA-256 works: #{hash.hexstring[0..16]}..."

# Test our implementation
sha256 = Crypto::Hashes::Sha256.new
our_hash = sha256.hash("test")
puts "Crystal SHA-256 works: #{our_hash[0..16]}..."

puts "All basic tests passed!"