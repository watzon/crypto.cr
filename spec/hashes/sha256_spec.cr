require "../spec_helper"

describe Crypto::Hashes::Sha256 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha256 = Crypto::Hashes::Sha256.new
      result = sha256.hash("")
      result.should eq "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    end

    it "produces correct hash for 'abc'" do
      sha256 = Crypto::Hashes::Sha256.new
      result = sha256.hash("abc")
      result.should eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    end

    it "produces correct hash for 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'" do
      sha256 = Crypto::Hashes::Sha256.new
      result = sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
      result.should eq "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    end

    it "produces correct hash for one million 'a' characters" do
      sha256 = Crypto::Hashes::Sha256.new
      input = "a" * 1_000_000
      result = sha256.hash(input)
      result.should eq "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    end

    it "produces correct hash for long message" do
      sha256 = Crypto::Hashes::Sha256.new
      # Test vector from NIST CAVP
      input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
      result = sha256.hash(input)
      result.should eq "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    end

    it "produces correct hash for binary data" do
      sha256 = Crypto::Hashes::Sha256.new
      input = Bytes[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
      result = sha256.hash_bytes(input).hexstring
      result.should eq "17e88db187afd62c16e5debf3e6527cd006bc012bc90b51a810cd80c2d511f43"
    end
  end

  describe "#hash_bytes" do
    it "produces correct bytes for 'abc'" do
      sha256 = Crypto::Hashes::Sha256.new
      result = sha256.hash_bytes("abc")
      expected = Bytes[
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
      ]
      result.should eq expected
    end

    it "produces correct bytes for empty input" do
      sha256 = Crypto::Hashes::Sha256.new
      result = sha256.hash_bytes(Bytes.empty)
      expected = Bytes[
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
      ]
      result.should eq expected
    end
  end

  describe "#output_size" do
    it "returns 32 bytes" do
      sha256 = Crypto::Hashes::Sha256.new
      sha256.output_size.should eq 32
    end
  end

  describe "#block_size" do
    it "returns 64 bytes" do
      sha256 = Crypto::Hashes::Sha256.new
      sha256.block_size.should eq 64
    end
  end
end