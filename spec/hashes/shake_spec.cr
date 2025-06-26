require "../spec_helper"

describe Crypto::Hashes::SHAKE128 do
  describe "#hash" do
    it "produces correct hash for empty string with default length" do
      shake = Crypto::Hashes::SHAKE128.new
      result = shake.hash("")
      result.should eq "7f9c2ba4e88f827d616045507605853e"
    end

    it "produces correct hash for 'abc' with default length" do
      shake = Crypto::Hashes::SHAKE128.new
      result = shake.hash("abc")
      result.should eq "5881092dd818bf5cf8a3ddb793fbcba7"
    end
  end

  describe "#shake" do
    it "produces correct output for empty string with custom length" do
      shake = Crypto::Hashes::SHAKE128.new
      result = shake.shake("", 32).hexstring
      result.should eq "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    end

    it "produces correct output for 'abc' with custom length" do
      shake = Crypto::Hashes::SHAKE128.new
      result = shake.shake("abc", 32).hexstring
      result.should eq "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
    end

    it "produces different outputs for different lengths" do
      shake = Crypto::Hashes::SHAKE128.new
      result16 = shake.shake("test", 16)
      result32 = shake.shake("test", 32)
      
      result16.size.should eq 16
      result32.size.should eq 32
      result32[0, 16].should eq result16
    end

    it "handles binary input" do
      shake = Crypto::Hashes::SHAKE128.new
      input = Bytes[0x00, 0x01, 0x02, 0x03]
      result = shake.shake(input, 16)
      result.size.should eq 16
    end
  end

  describe "#output_size" do
    it "returns default output size" do
      shake = Crypto::Hashes::SHAKE128.new(24)
      shake.output_size.should eq 24
    end
  end

  describe "#block_size" do
    it "returns 168 bytes" do
      shake = Crypto::Hashes::SHAKE128.new
      shake.block_size.should eq 168
    end
  end
end

describe Crypto::Hashes::SHAKE256 do
  describe "#hash" do
    it "produces correct hash for empty string with default length" do
      shake = Crypto::Hashes::SHAKE256.new
      result = shake.hash("")
      result.should eq "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    end

    it "produces correct hash for 'abc' with default length" do
      shake = Crypto::Hashes::SHAKE256.new
      result = shake.hash("abc")
      result.should eq "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    end
  end

  describe "#shake" do
    it "produces correct output for empty string with custom length" do
      shake = Crypto::Hashes::SHAKE256.new
      result = shake.shake("", 64).hexstring
      result.should eq "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    end

    it "produces correct output for 'abc' with custom length" do
      shake = Crypto::Hashes::SHAKE256.new
      result = shake.shake("abc", 64).hexstring
      result.should eq "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
    end

    it "produces different outputs for different lengths" do
      shake = Crypto::Hashes::SHAKE256.new
      result32 = shake.shake("test", 32)
      result64 = shake.shake("test", 64)
      
      result32.size.should eq 32
      result64.size.should eq 64
      result64[0, 32].should eq result32
    end

    it "handles binary input" do
      shake = Crypto::Hashes::SHAKE256.new
      input = Bytes[0x00, 0x01, 0x02, 0x03]
      result = shake.shake(input, 32)
      result.size.should eq 32
    end
  end

  describe "#output_size" do
    it "returns default output size" do
      shake = Crypto::Hashes::SHAKE256.new(48)
      shake.output_size.should eq 48
    end
  end

  describe "#block_size" do
    it "returns 136 bytes" do
      shake = Crypto::Hashes::SHAKE256.new
      shake.block_size.should eq 136
    end
  end
end