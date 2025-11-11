require "big"
require "./ec"

module Crypto::Asymmetric
  # P-256 (secp256r1) elliptic curve implementation
  class P256 < EllipticCurve
    # P-256 curve parameters from FIPS 186-4
    P256_P = BigInt.new("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    P256_A = BigInt.new("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
    P256_B = BigInt.new("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    P256_GX = BigInt.new("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    P256_GY = BigInt.new("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
    P256_N = BigInt.new("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    P256_H = BigInt.new("1", 16)

    def initialize
      g = ECPoint.new(P256_GX, P256_GY)
      super(P256_P, P256_A, P256_B, g, P256_N, P256_H)
    end

    def name : String
      "P-256"
    end

    def key_size : Int32
      256
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