# crypto.cr Benchmark Suite

This directory contains benchmarking tools to compare the performance of pure Crystal cryptographic implementations against OpenSSL equivalents.

## Available Benchmarks

### Quick Benchmark (`quick.cr`)
**Recommended for most users**

```bash
crystal run benchmark/quick.cr --release
```

- Fast execution (30-60 seconds)
- Covers SHA-1, SHA-256, and AES-256-CTR
- Clear, concise output with performance ratios
- Perfect for getting a quick performance overview

### Simple Benchmark (`simple.cr`)
Basic SHA-256 comparison:

```bash
crystal run benchmark/simple.cr --release
```

- Minimal example showing Crystal vs OpenSSL for SHA-256
- Good starting point for understanding benchmark structure

### Comprehensive Benchmark (`run.cr`)
Full benchmark suite with detailed reporting:

```bash
crystal run benchmark/run.cr --release
```

- All implemented algorithms (SHA family, AES, RSA, SCrypt)
- Multiple data sizes (64B, 1KB, 64KB)
- Detailed performance analysis
- May take several minutes to complete

### Test Benchmark (`test.cr`)
Basic functionality test:

```bash
crystal run benchmark/test.cr
```

- Verifies that both Crystal and OpenSSL implementations work
- Quick sanity check before running performance benchmarks

## Benchmark Results

### Latest Results (Apple M1, Crystal 1.16.0)

| Algorithm | Crystal (MB/s) | OpenSSL (MB/s) | Ratio |
|-----------|---------------|----------------|-------|
| SHA-1     | 56.6          | 1192.6         | 21.1x |
| SHA-256   | 54.5          | 215.2          | 3.9x  |
| AES-256-CTR | 51.2        | 730.4          | 14.3x |

## Understanding the Results

### Why OpenSSL is Faster

1. **Optimized C Implementation**: Hand-tuned assembly for specific architectures
2. **Hardware Acceleration**: Uses CPU crypto instructions (AES-NI, SHA extensions)
3. **Memory Management**: Direct memory control without garbage collection
4. **Constant-time Operations**: Protection against timing attacks

### Why Pure Crystal is Slower

1. **Educational Focus**: Optimized for readability and learning, not performance
2. **Garbage Collection**: Memory allocation overhead
3. **Generic Implementation**: No hardware-specific optimizations
4. **Safety Checks**: Additional bounds checking and type safety

### When to Use Each

**Pure Crystal Implementations:**
- ✅ Learning cryptographic algorithms
- ✅ Educational projects and experiments
- ✅ Understanding protocol implementations (MTProto)
- ✅ Prototyping and research

**OpenSSL Implementations:**
- ✅ Production systems
- ✅ High-performance applications
- ✅ Security-critical systems
- ✅ Compliance requirements

## Adding New Benchmarks

To add a benchmark for a new algorithm:

1. Add the Crystal implementation to the benchmark
2. Find the equivalent OpenSSL function
3. Create fair comparison with identical data
4. Measure operations per second and calculate throughput
5. Include relative performance ratio

Example structure:
```crystal
# Crystal implementation
crystal_time = Benchmark.measure do
  iterations.times { crystal_algorithm.process(data) }
end

# OpenSSL implementation  
openssl_time = Benchmark.measure do
  iterations.times { openssl_algorithm.process(data) }
end

# Calculate and display results
crystal_ops = iterations.to_f / crystal_time.real
openssl_ops = iterations.to_f / openssl_time.real
ratio = openssl_ops / crystal_ops

puts "Crystal: #{crystal_ops.round(2)} ops/s"
puts "OpenSSL: #{openssl_ops.round(2)} ops/s" 
puts "Ratio: #{ratio.round(2)}x faster"
```

## Notes

- Always use `--release` flag for meaningful performance comparisons
- Results vary by hardware, OS, and Crystal version
- Benchmarks use realistic data sizes and iteration counts
- Pure Crystal implementations prioritize correctness and educational value over performance