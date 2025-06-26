#!/usr/bin/env crystal

require "benchmark"
require "openssl"
require "file_utils"
require "json"
require "../src/crypto"

# Comprehensive benchmark suite with detailed reporting
module ComprehensiveBenchmark
  extend self

  struct BenchmarkResult
    include JSON::Serializable
    
    property algorithm : String
    property implementation : String
    property data_size : String
    property operations_per_second : Float64
    property throughput_mb_per_second : Float64
    property relative_performance : Float64?
    
    def initialize(@algorithm : String, @implementation : String, @data_size : String, 
                   @operations_per_second : Float64, @throughput_mb_per_second : Float64, 
                   @relative_performance : Float64? = nil)
    end
  end

  struct BenchmarkReport
    include JSON::Serializable
    
    property timestamp : String
    property crystal_version : String
    property platform : String
    property results : Array(BenchmarkResult)
    
    def initialize(@timestamp : String, @crystal_version : String, 
                   @platform : String, @results : Array(BenchmarkResult))
    end
  end

  # Test configurations
  ITERATIONS = 1000
  SCRYPT_ITERATIONS = 3
  RSA_ITERATIONS = 100

  def run_comprehensive_benchmarks
    puts "🔐 crypto.cr Comprehensive Benchmark Suite"
    puts "=" * 60
    puts "Crystal Version: #{Crystal::DESCRIPTION}"
    puts "Platform: #{{% if flag?(:darwin) %}"macOS"{% elsif flag?(:linux) %}"Linux"{% else %}"Unknown"{% end %}}"
    puts "Timestamp: #{Time.local}"
    puts "=" * 60

    results = [] of BenchmarkResult
    
    # Hash function benchmarks
    results.concat(benchmark_hash_functions)
    
    # Symmetric encryption benchmarks
    results.concat(benchmark_symmetric_ciphers)
    
    # Asymmetric encryption benchmarks
    results.concat(benchmark_asymmetric_operations)
    
    # Key derivation function benchmarks
    results.concat(benchmark_kdf_functions)
    
    # Generate report
    generate_report(results)
    
    puts "\n🎯 Benchmark Summary"
    puts "=" * 60
    print_performance_summary(results)
  end

  def benchmark_hash_functions
    puts "\n📊 Hash Function Benchmarks"
    puts "-" * 40

    results = [] of BenchmarkResult
    test_sizes = [
      {size: 64, name: "64B"},
      {size: 1024, name: "1KB"},
      {size: 65536, name: "64KB"}
    ]
    
    hash_algorithms = [
      {name: "SHA-1", crystal: Crypto::Hashes::Sha1.new, openssl: "SHA1"},
      {name: "SHA-256", crystal: Crypto::Hashes::Sha256.new, openssl: "SHA256"},
      {name: "SHA-512", crystal: Crypto::Hashes::Sha512.new, openssl: "SHA512"}
    ]

    hash_algorithms.each do |algo|
      puts "\n#{algo[:name]} Performance:"
      
      test_sizes.each do |test_size|
        data = generate_test_data(test_size[:size])
        
        # Crystal implementation
        crystal_time = Benchmark.measure do
          ITERATIONS.times { algo[:crystal].hash_bytes(data) }
        end
        crystal_ops = ITERATIONS.to_f / crystal_time.real
        crystal_throughput = calculate_throughput(test_size[:size], crystal_ops)
        
        # OpenSSL implementation
        openssl_time = Benchmark.measure do
          ITERATIONS.times do
            digest = OpenSSL::Digest.new(algo[:openssl])
            digest.update(data)
            digest.final
          end
        end
        openssl_ops = ITERATIONS.to_f / openssl_time.real
        openssl_throughput = calculate_throughput(test_size[:size], openssl_ops)
        
        # Calculate relative performance
        relative_perf = openssl_ops / crystal_ops
        
        # Store results
        results << BenchmarkResult.new(
          algo[:name], "Crystal", test_size[:name], 
          crystal_ops, crystal_throughput
        )
        results << BenchmarkResult.new(
          algo[:name], "OpenSSL", test_size[:name], 
          openssl_ops, openssl_throughput, relative_perf
        )
        
        # Print results
        puts "  #{test_size[:name]}: Crystal #{crystal_throughput.round(2)} MB/s, OpenSSL #{openssl_throughput.round(2)} MB/s (#{relative_perf.round(2)}x faster)"
      end
    end
    
    results
  end

  def benchmark_symmetric_ciphers
    puts "\n🔒 Symmetric Cipher Benchmarks"
    puts "-" * 40

    results = [] of BenchmarkResult
    key = generate_random_data(32)
    
    test_sizes = [
      {size: 1024, name: "1KB"},
      {size: 65536, name: "64KB"}
    ]

    puts "\nAES-256-CTR Performance:"
    
    test_sizes.each do |test_size|
      data = generate_test_data(test_size[:size])
      nonce = generate_random_data(12)
      iv = generate_random_data(16)
      
      # Crystal AES-CTR
      crystal_time = Benchmark.measure do
        ITERATIONS.times do
          cipher = Crypto::Ciphers::AES_CTR.new(key, nonce)
          cipher.encrypt(data)
        end
      end
      crystal_ops = ITERATIONS.to_f / crystal_time.real
      crystal_throughput = calculate_throughput(test_size[:size], crystal_ops)
      
      # OpenSSL AES-CTR
      openssl_time = Benchmark.measure do
        ITERATIONS.times do
          cipher = OpenSSL::Cipher.new("AES-256-CTR")
          cipher.encrypt
          cipher.key = key
          cipher.iv = iv
          cipher.update(data) + cipher.final
        end
      end
      openssl_ops = ITERATIONS.to_f / openssl_time.real
      openssl_throughput = calculate_throughput(test_size[:size], openssl_ops)
      
      relative_perf = openssl_ops / crystal_ops
      
      results << BenchmarkResult.new(
        "AES-256-CTR", "Crystal", test_size[:name],
        crystal_ops, crystal_throughput
      )
      results << BenchmarkResult.new(
        "AES-256-CTR", "OpenSSL", test_size[:name],
        openssl_ops, openssl_throughput, relative_perf
      )
      
      puts "  #{test_size[:name]}: Crystal #{crystal_throughput.round(2)} MB/s, OpenSSL #{openssl_throughput.round(2)} MB/s (#{relative_perf.round(2)}x faster)"
    end
    
    results
  end

  def benchmark_asymmetric_operations
    puts "\n🔑 Asymmetric Cryptography Benchmarks"
    puts "-" * 40

    results = [] of BenchmarkResult
    
    # RSA benchmarks
    rsa_key = Crypto::Asymmetric::RSAKey.new(
      TestKeys::RSA_N, TestKeys::RSA_E, TestKeys::RSA_D,
      TestKeys::RSA_P, TestKeys::RSA_Q, TestKeys::RSA_DP, TestKeys::RSA_DQ, TestKeys::RSA_QINV
    )
    crystal_rsa = Crypto::Asymmetric::RSA.new(rsa_key)
    
    test_message = "Hello RSA benchmark test message!".to_slice
    
    # RSA Encryption
    encrypt_time = Benchmark.measure do
      RSA_ITERATIONS.times { crystal_rsa.encrypt(test_message) }
    end
    encrypt_ops = RSA_ITERATIONS.to_f / encrypt_time.real
    
    # RSA Decryption
    test_ciphertext = crystal_rsa.encrypt(test_message)
    decrypt_time = Benchmark.measure do
      RSA_ITERATIONS.times { crystal_rsa.decrypt(test_ciphertext) }
    end
    decrypt_ops = RSA_ITERATIONS.to_f / decrypt_time.real
    
    results << BenchmarkResult.new("RSA-2048", "Crystal Encrypt", "32B", encrypt_ops, 0.0)
    results << BenchmarkResult.new("RSA-2048", "Crystal Decrypt", "256B", decrypt_ops, 0.0)
    
    puts "\nRSA-2048 Performance:"
    puts "  Encryption: #{encrypt_ops.round(2)} ops/s"
    puts "  Decryption: #{decrypt_ops.round(2)} ops/s"
    puts "  Note: OpenSSL RSA not available in Crystal bindings"
    
    results
  end

  def benchmark_kdf_functions
    puts "\n🔐 Key Derivation Function Benchmarks"
    puts "-" * 40

    results = [] of BenchmarkResult
    
    password = "benchmark_password"
    salt = generate_random_data(16)
    
    # SCrypt benchmark
    scrypt_time = Benchmark.measure do
      SCRYPT_ITERATIONS.times do
        Crypto::KDF::SCrypt.hash(
          password: password,
          salt: String.new(salt),
          n: 10,  # Lower for benchmarking
          r: 8,
          p: 1,
          output_length: 32
        )
      end
    end
    scrypt_ops = SCRYPT_ITERATIONS.to_f / scrypt_time.real
    
    results << BenchmarkResult.new("SCrypt", "Crystal", "N=10", scrypt_ops, 0.0)
    
    puts "\nSCrypt Performance (N=10, r=8, p=1):"
    puts "  Crystal: #{scrypt_ops.round(3)} ops/s"
    puts "  Note: Lower N value used for benchmarking; production uses N=14+"
    
    results
  end

  def generate_test_data(size : Int32) : Bytes
    Bytes.new(size) { |i| (i % 256).to_u8 }
  end

  def generate_random_data(size : Int32) : Bytes
    Random::Secure.random_bytes(size)
  end

  def calculate_throughput(data_size : Int32, ops_per_second : Float64) : Float64
    (data_size * ops_per_second) / (1024 * 1024)
  end

  def generate_report(results : Array(BenchmarkResult))
    timestamp = Time.local.to_s("%Y%m%d_%H%M%S")
    
    report = BenchmarkReport.new(
      Time.local.to_s,
      Crystal::DESCRIPTION,
      {% if flag?(:darwin) %}"macOS"{% elsif flag?(:linux) %}"Linux"{% else %}"Unknown"{% end %},
      results
    )
    
    # Save JSON report
    json_file = "benchmark/reports/benchmark_#{timestamp}.json"
    FileUtils.mkdir_p("benchmark/reports")
    File.write(json_file, report.to_json)
    
    # Save Markdown report
    md_file = "benchmark/reports/benchmark_#{timestamp}.md"
    File.write(md_file, generate_markdown_report(report))
    
    puts "\n📝 Reports generated:"
    puts "  JSON: #{json_file}"
    puts "  Markdown: #{md_file}"
  end

  def generate_markdown_report(report : BenchmarkReport) : String
    md = String.build do |str|
      str << "# crypto.cr Benchmark Report\n\n"
      str << "**Generated:** #{report.timestamp}\n"
      str << "**Crystal Version:** #{report.crystal_version}\n"
      str << "**Platform:** #{report.platform}\n\n"
      
      # Group results by algorithm
      algorithms = report.results.group_by(&.algorithm)
      
      algorithms.each do |algo_name, algo_results|
        str << "## #{algo_name}\n\n"
        str << "| Implementation | Data Size | Ops/sec | Throughput (MB/s) | Relative Performance |\n"
        str << "|----------------|-----------|---------|-------------------|----------------------|\n"
        
        algo_results.each do |result|
          relative = if rel_perf = result.relative_performance
                      "#{rel_perf.round(2)}x"
                    else
                      "-"
                    end
          throughput = result.throughput_mb_per_second > 0 ? result.throughput_mb_per_second.round(2).to_s : "-"
          
          str << "| #{result.implementation} | #{result.data_size} | #{result.operations_per_second.round(2)} | #{throughput} | #{relative} |\n"
        end
        str << "\n"
      end
      
      str << "## Notes\n\n"
      str << "- **Crystal implementations** are pure Crystal code for educational/experimental use\n"
      str << "- **OpenSSL implementations** use Crystal's OpenSSL bindings\n" 
      str << "- **Relative Performance** shows how many times faster OpenSSL is\n"
      str << "- Production systems should use OpenSSL for security and performance\n"
    end
    
    md
  end

  def print_performance_summary(results : Array(BenchmarkResult))
    # Calculate average relative performance for each algorithm
    crystal_results = results.select { |r| r.implementation.includes?("Crystal") && !r.implementation.includes?("Encrypt") && !r.implementation.includes?("Decrypt") }
    openssl_results = results.select { |r| r.implementation == "OpenSSL" }
    
    if openssl_results.size > 0
      avg_ratio = openssl_results.map(&.relative_performance.not_nil!).sum / openssl_results.size
      puts "Average Performance: OpenSSL is #{avg_ratio.round(2)}x faster than Crystal"
      puts "This is expected for educational pure-Crystal implementations."
    end
    
    puts "Crystal implementations provide excellent learning value!"
    puts "For production use, prefer OpenSSL bindings for security and performance."
  end
end

# Test keys module for RSA benchmarks
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

# Run comprehensive benchmarks if this file is executed directly
if PROGRAM_NAME.includes?("comprehensive.cr")
  ComprehensiveBenchmark.run_comprehensive_benchmarks
end