#!/usr/bin/env crystal

require "benchmark"
require "openssl"
require "../src/crypto"

# Benchmark runner for crypto.cr library
# Compares pure Crystal implementations against OpenSSL equivalents

module CryptoBenchmark
  extend self

  # Benchmark configuration
  WARM_UP_ITERATIONS = 2
  BENCHMARK_ITERATIONS = 5
  
  # Test data sizes (in bytes)
  SMALL_DATA_SIZE = 64        # 64 bytes
  MEDIUM_DATA_SIZE = 1024     # 1 KB  
  LARGE_DATA_SIZE = 65536     # 64 KB
  HUGE_DATA_SIZE = 1048576    # 1 MB

  # Generate test data of specified size
  def generate_test_data(size : Int32) : Bytes
    Bytes.new(size) { |i| (i % 256).to_u8 }
  end

  # Generate random test data
  def generate_random_data(size : Int32) : Bytes
    Random::Secure.random_bytes(size)
  end

  # Print benchmark header
  def print_header(algorithm : String, description : String)
    puts "\n" + "=" * 80
    puts "#{algorithm} - #{description}"
    puts "=" * 80
    puts "%-30s %15s %15s %15s" % ["Implementation", "Small (64B)", "Medium (1KB)", "Large (64KB)"]
    puts "-" * 80
  end

  # Print benchmark result
  def print_result(name : String, small_ops : Float64, medium_ops : Float64, large_ops : Float64)
    puts "%-30s %12.2f ops/s %12.2f ops/s %12.2f ops/s" % [name, small_ops, medium_ops, large_ops]
  end

  # Print benchmark result with throughput
  def print_throughput_result(name : String, small_mb : Float64, medium_mb : Float64, large_mb : Float64)
    puts "%-30s %12.2f MB/s %12.2f MB/s %12.2f MB/s" % [name, small_mb, medium_mb, large_mb]
  end

  # Run benchmark for a given block with specified data
  def benchmark_operation(data : Bytes, &block : Bytes ->)
    # Warm up
    WARM_UP_ITERATIONS.times { block.call(data) }
    
    # Actual benchmark
    elapsed = Benchmark.measure do
      BENCHMARK_ITERATIONS.times { block.call(data) }
    end
    
    # Calculate operations per second
    BENCHMARK_ITERATIONS / elapsed.real
  end

  # Calculate throughput in MB/s
  def calculate_throughput(data_size : Int32, ops_per_second : Float64) : Float64
    (data_size * ops_per_second) / (1024 * 1024)
  end

  def run_all_benchmarks
    puts "crypto.cr Benchmark Suite"
    puts "Comparing pure Crystal implementations vs OpenSSL"
    puts "Platform: #{Crystal::DESCRIPTION}"
    puts "Time: #{Time.local}"
    
    benchmark_sha_hashes
    benchmark_aes_ciphers  
    benchmark_rsa_operations
    benchmark_scrypt_kdf
    
    puts "\n" + "=" * 80
    puts "Benchmark completed!"
    puts "Note: Pure Crystal implementations are for educational/experimental use only."
    puts "Use OpenSSL for production systems requiring security and performance."
    puts "=" * 80
  end

  def benchmark_sha_hashes
    small_data = generate_test_data(SMALL_DATA_SIZE)
    medium_data = generate_test_data(MEDIUM_DATA_SIZE)  
    large_data = generate_test_data(LARGE_DATA_SIZE)

    # SHA-1 Benchmark
    print_header("SHA-1", "Hash Function Comparison")
    
    # Crystal implementation
    sha1_crystal = Crypto::Hashes::Sha1.new
    small_ops = benchmark_operation(small_data) { |data| sha1_crystal.hash_bytes(data) }
    medium_ops = benchmark_operation(medium_data) { |data| sha1_crystal.hash_bytes(data) }
    large_ops = benchmark_operation(large_data) { |data| sha1_crystal.hash_bytes(data) }
    
    print_result("Crystal SHA-1", small_ops, medium_ops, large_ops)
    print_throughput_result("Crystal SHA-1 (MB/s)", 
      calculate_throughput(SMALL_DATA_SIZE, small_ops),
      calculate_throughput(MEDIUM_DATA_SIZE, medium_ops), 
      calculate_throughput(LARGE_DATA_SIZE, large_ops))

    # OpenSSL implementation
    small_ops = benchmark_operation(small_data) { |data| OpenSSL::Digest.new("SHA1").update(data).final }
    medium_ops = benchmark_operation(medium_data) { |data| OpenSSL::Digest.new("SHA1").update(data).final }
    large_ops = benchmark_operation(large_data) { |data| OpenSSL::Digest.new("SHA1").update(data).final }
    
    print_result("OpenSSL SHA-1", small_ops, medium_ops, large_ops)
    print_throughput_result("OpenSSL SHA-1 (MB/s)",
      calculate_throughput(SMALL_DATA_SIZE, small_ops),
      calculate_throughput(MEDIUM_DATA_SIZE, medium_ops),
      calculate_throughput(LARGE_DATA_SIZE, large_ops))

    # SHA-256 Benchmark
    print_header("SHA-256", "Hash Function Comparison")
    
    # Crystal implementation
    sha256_crystal = Crypto::Hashes::Sha256.new
    small_ops = benchmark_operation(small_data) { |data| sha256_crystal.hash_bytes(data) }
    medium_ops = benchmark_operation(medium_data) { |data| sha256_crystal.hash_bytes(data) }
    large_ops = benchmark_operation(large_data) { |data| sha256_crystal.hash_bytes(data) }
    
    print_result("Crystal SHA-256", small_ops, medium_ops, large_ops)
    print_throughput_result("Crystal SHA-256 (MB/s)",
      calculate_throughput(SMALL_DATA_SIZE, small_ops),
      calculate_throughput(MEDIUM_DATA_SIZE, medium_ops),
      calculate_throughput(LARGE_DATA_SIZE, large_ops))

    # OpenSSL implementation  
    small_ops = benchmark_operation(small_data) { |data| OpenSSL::Digest.new("SHA256").update(data).final }
    medium_ops = benchmark_operation(medium_data) { |data| OpenSSL::Digest.new("SHA256").update(data).final }
    large_ops = benchmark_operation(large_data) { |data| OpenSSL::Digest.new("SHA256").update(data).final }
    
    print_result("OpenSSL SHA-256", small_ops, medium_ops, large_ops)
    print_throughput_result("OpenSSL SHA-256 (MB/s)",
      calculate_throughput(SMALL_DATA_SIZE, small_ops),
      calculate_throughput(MEDIUM_DATA_SIZE, medium_ops),
      calculate_throughput(LARGE_DATA_SIZE, large_ops))

    # SHA-512 Benchmark
    print_header("SHA-512", "Hash Function Comparison")
    
    # Crystal implementation
    sha512_crystal = Crypto::Hashes::Sha512.new
    small_ops = benchmark_operation(small_data) { |data| sha512_crystal.hash_bytes(data) }
    medium_ops = benchmark_operation(medium_data) { |data| sha512_crystal.hash_bytes(data) }
    large_ops = benchmark_operation(large_data) { |data| sha512_crystal.hash_bytes(data) }
    
    print_result("Crystal SHA-512", small_ops, medium_ops, large_ops)
    print_throughput_result("Crystal SHA-512 (MB/s)",
      calculate_throughput(SMALL_DATA_SIZE, small_ops),
      calculate_throughput(MEDIUM_DATA_SIZE, medium_ops),
      calculate_throughput(LARGE_DATA_SIZE, large_ops))

    # OpenSSL implementation
    small_ops = benchmark_operation(small_data) { |data| OpenSSL::Digest.new("SHA512").update(data).final }
    medium_ops = benchmark_operation(medium_data) { |data| OpenSSL::Digest.new("SHA512").update(data).final }
    large_ops = benchmark_operation(large_data) { |data| OpenSSL::Digest.new("SHA512").update(data).final }
    
    print_result("OpenSSL SHA-512", small_ops, medium_ops, large_ops)
    print_throughput_result("OpenSSL SHA-512 (MB/s)",
      calculate_throughput(SMALL_DATA_SIZE, small_ops),
      calculate_throughput(MEDIUM_DATA_SIZE, medium_ops),
      calculate_throughput(LARGE_DATA_SIZE, large_ops))
  end

  def benchmark_aes_ciphers
    # AES test data - needs to be block-aligned (16 bytes)
    small_data = generate_test_data(64)   # 4 blocks
    medium_data = generate_test_data(1024) # 64 blocks  
    large_data = generate_test_data(65536) # 4096 blocks

    key = generate_random_data(32) # 256-bit key

    print_header("AES-256-CTR", "Symmetric Encryption Comparison")

    # Crystal AES-CTR implementation
    nonce = generate_random_data(12)
    small_ops = benchmark_operation(small_data) do |data|
      cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
      cipher.encrypt(data)
    end
    medium_ops = benchmark_operation(medium_data) do |data|
      cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
      cipher.encrypt(data)
    end
    large_ops = benchmark_operation(large_data) do |data|
      cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
      cipher.encrypt(data)
    end

    print_result("Crystal AES-256-CTR", small_ops, medium_ops, large_ops)
    print_throughput_result("Crystal AES-256-CTR (MB/s)",
      calculate_throughput(64, small_ops),
      calculate_throughput(1024, medium_ops),
      calculate_throughput(65536, large_ops))

    # OpenSSL AES-CTR implementation
    iv = generate_random_data(16)
    small_ops = benchmark_operation(small_data) do |data|
      cipher = OpenSSL::Cipher.new("AES-256-CTR")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.update(data) + cipher.final
    end
    medium_ops = benchmark_operation(medium_data) do |data|
      cipher = OpenSSL::Cipher.new("AES-256-CTR")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.update(data) + cipher.final
    end
    large_ops = benchmark_operation(large_data) do |data|
      cipher = OpenSSL::Cipher.new("AES-256-CTR")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.update(data) + cipher.final
    end

    print_result("OpenSSL AES-256-CTR", small_ops, medium_ops, large_ops)
    print_throughput_result("OpenSSL AES-256-CTR (MB/s)",
      calculate_throughput(64, small_ops),
      calculate_throughput(1024, medium_ops),
      calculate_throughput(65536, large_ops))
  end

  def benchmark_rsa_operations
    print_header("RSA-2048", "Asymmetric Encryption Comparison")

    # Use our test RSA key for benchmarking
    rsa_key = Crypto::Asymmetric::RSAKey.new(
      TestKeys::RSA_N, TestKeys::RSA_E, TestKeys::RSA_D, 
      TestKeys::RSA_P, TestKeys::RSA_Q, TestKeys::RSA_DP, TestKeys::RSA_DQ, TestKeys::RSA_QINV
    )
    crystal_rsa = Crypto::Asymmetric::RSA.new(rsa_key)

    # Test data - small for RSA (asymmetric encryption is typically used for small data)
    test_message = "Hello RSA benchmark!".to_slice

    # Crystal RSA encryption benchmark
    encrypt_ops = benchmark_operation(test_message) { |data| crystal_rsa.encrypt(data) }
    
    # For decryption benchmark, we need ciphertext
    test_ciphertext = crystal_rsa.encrypt(test_message)
    decrypt_ops = benchmark_operation(test_ciphertext) { |data| crystal_rsa.decrypt(data) }

    puts "%-30s %15s %15s" % ["Implementation", "Encrypt ops/s", "Decrypt ops/s"]
    puts "-" * 62
    puts "%-30s %15.2f %15.2f" % ["Crystal RSA-2048", encrypt_ops, decrypt_ops]

    # Note about OpenSSL RSA
    puts "%-30s %15s %15s" % ["OpenSSL RSA-2048", "N/A", "N/A"]
    puts "Note: Crystal's OpenSSL bindings don't expose RSA operations directly."
    puts "      Consider using openssl command-line tool for comparison."
  end

  def benchmark_scrypt_kdf
    print_header("SCrypt", "Key Derivation Function Comparison")

    password = "test_password"
    salt = generate_random_data(16)
    
    # Different SCrypt parameters for different security levels
    test_params = [
      {n: 10, r: 8, p: 1, name: "SCrypt (N=10, r=8, p=1)"},
    ]

    puts "%-30s %15s" % ["Implementation", "ops/s"]
    puts "-" * 47

    test_params.each do |params|
      # Crystal implementation - reduce iterations for SCrypt
      scrypt_iterations = 2
      crystal_ops = scrypt_iterations.to_f / Benchmark.measure do
        scrypt_iterations.times do
          Crypto::KDF::SCrypt.hash(
            password: password,
            salt: String.new(salt),
            n: params[:n],
            r: params[:r], 
            p: params[:p],
            output_length: 32
          )
        end
      end.real

      puts "%-30s %15.2f" % ["Crystal #{params[:name]}", crystal_ops]

      # Note: Crystal's OpenSSL bindings don't expose SCrypt directly,
      # so we'll note that comparison would require additional binding work
      puts "%-30s %15s" % ["OpenSSL #{params[:name]}", "N/A (binding needed)"]
    end
  end
end

# Include test keys for benchmarking
module TestKeys
  RSA_N = BigInt.new("22274662505604405022976253196135356781221269075551173705290652494553646426426840708252853109653197522107807339369102838577803052351939878071837335685680221164108948151093450178668287955737754135057005810984001103276919610039221814198857302748546134463981659147598994641856937797585676243881581775868592921173410041301386396857361031631748087439497792259132490497976186129020025554172246817396644416152177664340618473875663049036544648314687519239206615701541791803760271654167841290267796216795518429594118807842751249699946218393756701977519278073125710435218720742993877745533977410832355432072638303099366574235973")
  RSA_E = BigInt.new("65537")
  RSA_D = BigInt.new("224745114695987195346797189769817121192342709861730222814951004196463046820494505673622520389370536666215841481267364267659066914379972296183872289274090151285030470801387673080006796324695819488326366670936581313484948840173267385431044927941103978123928042347831533438025849804744318724792040363353633354070501295753922674775189896506947253250252957897338887775930807454204606394897173549708380216812648845150504906747472423026210833729580930426315281027846556871585707979574596939315217063640699570193120988914399821762570323784337027406618718605093603618163163856220616291699371730127512940095444084637856604473")
  RSA_P = BigInt.new("169277217473691128268644981708090438498119516741350829538291188950138569556862549359241551825204387422288671704402927824069495073071893089899774392936256292684733548820835448967380320071737781810793113606883375688419012203316255647830072694656079250480227223679758089212493736235298220654586838868074045528873")
  RSA_Q = BigInt.new("131586889470618263320560188980182806274790925048381727914375351221180308921809881758025753900885462378248682967465640777134844114756578228929639686341671922881795127868925902378825907007605936657811032231356688954659801563061851599787396741460906042472241315691994091241556680151133860862232758787192402752701")
  RSA_DP = BigInt.new("43390572902948521656239483768164720330956707840425295411962001360657000320212001872009686575699353102934638386899992134466689774212044066973256481482768046459417411334684448589392587345852312382921304232449361859556448815226662475058324171041205354667093964182007967112938985229973523487135576943478888121817")
  RSA_DQ = BigInt.new("82883055332821488775389850025206314647044713459529696634045111897253813148180599035221372980584278910754316384591629938509946519632445020220875631356092237614790162479656701560918770179806415692424728176608696157107536330976291774710831095221114811987947594668134276613996059579150796899354079111575177161473")
  RSA_QINV = BigInt.new("89351625475357714787743720780648791313981608163676934689024753498918393832302774036643822947123414661257376810020631333500712156354052012124643276480514471332004348186687855099189856454502460766192982477134027065099147305392877622504838681877121638386932319051202368331102692378032406630414192677345716595066")
end

# Run benchmarks if this file is executed directly
if PROGRAM_NAME.includes?("run.cr")
  CryptoBenchmark.run_all_benchmarks
end