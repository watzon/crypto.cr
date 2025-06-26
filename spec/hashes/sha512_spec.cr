require "../spec_helper"

describe Crypto::Hashes::Sha512 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha512 = Crypto::Hashes::Sha512.new
      result = sha512.hash("")
      result.should eq "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    end

    it "produces correct hash for 'abc'" do
      sha512 = Crypto::Hashes::Sha512.new
      result = sha512.hash("abc")
      result.should eq "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    end

    it "produces correct hash for 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'" do
      sha512 = Crypto::Hashes::Sha512.new
      result = sha512.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
      result.should eq "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    end

    it "produces correct hash for one million 'a' characters" do
      sha512 = Crypto::Hashes::Sha512.new
      input = "a" * 1_000_000
      result = sha512.hash(input)
      result.should eq "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    end

    it "produces correct hash for long message" do
      sha512 = Crypto::Hashes::Sha512.new
      # Test vector from NIST CAVP
      input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
      result = sha512.hash(input)
      result.should eq "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    end


  end

  describe "#hash_bytes" do
    it "produces correct bytes for 'abc'" do
      sha512 = Crypto::Hashes::Sha512.new
      result = sha512.hash_bytes("abc")
      expected = Bytes[
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
      ]
      result.should eq expected
    end

    it "produces correct bytes for empty input" do
      sha512 = Crypto::Hashes::Sha512.new
      result = sha512.hash_bytes(Bytes.empty)
      expected = Bytes[
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
      ]
      result.should eq expected
    end
  end

  describe "#output_size" do
    it "returns 64 bytes" do
      sha512 = Crypto::Hashes::Sha512.new
      sha512.output_size.should eq 64
    end
  end

  describe "#block_size" do
    it "returns 128 bytes" do
      sha512 = Crypto::Hashes::Sha512.new
      sha512.block_size.should eq 128
    end
  end
end