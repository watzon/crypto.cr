require "../spec_helper"

describe Crypto::Hashes::Sha1 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha1 = Crypto::Hashes::Sha1.new
      result = sha1.hash("")
      result.should eq "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    end

    it "produces correct hash for 'abc'" do
      sha1 = Crypto::Hashes::Sha1.new
      result = sha1.hash("abc")
      result.should eq "a9993e364706816aba3e25717850c26c9cd0d89d"
    end

    it "produces correct hash for 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'" do
      sha1 = Crypto::Hashes::Sha1.new
      result = sha1.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
      result.should eq "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    end

    it "produces correct hash for one million 'a' characters" do
      sha1 = Crypto::Hashes::Sha1.new
      input = "a" * 1_000_000
      result = sha1.hash(input)
      result.should eq "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    end

    it "produces correct hash for long message" do
      sha1 = Crypto::Hashes::Sha1.new
      # Test vector from NIST CAVP
      input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
      result = sha1.hash(input)
      result.should eq "a49b2446a02c645bf419f995b67091253a04a259"
    end
  end

  describe "#hash_bytes" do
    it "produces correct bytes for 'abc'" do
      sha1 = Crypto::Hashes::Sha1.new
      result = sha1.hash_bytes("abc")
      expected = Bytes[
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
      ]
      result.should eq expected
    end

    it "produces correct bytes for empty input" do
      sha1 = Crypto::Hashes::Sha1.new
      result = sha1.hash_bytes(Bytes.empty)
      expected = Bytes[
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09
      ]
      result.should eq expected
    end
  end

  describe "#output_size" do
    it "returns 20 bytes" do
      sha1 = Crypto::Hashes::Sha1.new
      sha1.output_size.should eq 20
    end
  end

  describe "#block_size" do
    it "returns 64 bytes" do
      sha1 = Crypto::Hashes::Sha1.new
      sha1.block_size.should eq 64
    end
  end
end