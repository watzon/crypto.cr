require "benchmark"
require "openssl"
require "../src/crypto"

puts "crypto.cr Simple Benchmark"
puts "=" * 40

# Test data
test_data = Bytes.new(1024) { |i| (i % 256).to_u8 }

# SHA-256 benchmark
puts "\nSHA-256 Benchmark (1KB data, 1000 iterations):"
puts "-" * 50

# Crystal implementation
crystal_time = Benchmark.measure do
  sha256 = Crypto::Hashes::Sha256.new
  1000.times { sha256.hash_bytes(test_data) }
end

crystal_ops_per_sec = 1000.0 / crystal_time.real
crystal_mb_per_sec = (1024 * crystal_ops_per_sec) / (1024 * 1024)

puts "Crystal SHA-256:  #{crystal_ops_per_sec.round(2)} ops/s (#{crystal_mb_per_sec.round(2)} MB/s)"

# OpenSSL implementation  
openssl_time = Benchmark.measure do
  1000.times do
    digest = OpenSSL::Digest.new("SHA256")
    digest.update(test_data)
    digest.final
  end
end

openssl_ops_per_sec = 1000.0 / openssl_time.real
openssl_mb_per_sec = (1024 * openssl_ops_per_sec) / (1024 * 1024)

puts "OpenSSL SHA-256: #{openssl_ops_per_sec.round(2)} ops/s (#{openssl_mb_per_sec.round(2)} MB/s)"

performance_ratio = openssl_ops_per_sec / crystal_ops_per_sec
puts "OpenSSL is #{performance_ratio.round(2)}x faster"

puts "\n" + "=" * 40
puts "Benchmark complete!"