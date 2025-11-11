require "big"
require "./ec"

module Crypto::Asymmetric
  # P-384 (secp384r1) elliptic curve implementation
  class P384 < EllipticCurve
    # P-384 curve parameters from FIPS 186-4
    P384_P = BigInt.new("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
    P384_A = BigInt.new("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16)
    P384_B = BigInt.new("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
    P384_GX = BigInt.new("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
    P384_GY = BigInt.new("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
    P384_N = BigInt.new("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
    P384_H = BigInt.new("1", 16)

    def initialize
      g = ECPoint.new(P384_GX, P384_GY)
      super(P384_P, P384_A, P384_B, g, P384_N, P384_H)
    end

    def name : String
      "P-384"
    end

    def key_size : Int32
      384
    end

    def self.instance
      @@instance ||= new
    end

    # Get the singleton instance
    def self.get
      instance
    end
  end
end