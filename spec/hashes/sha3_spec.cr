require "../spec_helper"

describe Crypto::Hashes::SHA3_224 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha3 = Crypto::Hashes::SHA3_224.new
      result = sha3.hash("")
      result.should eq "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    end

    it "produces correct hash for 'abc'" do
      sha3 = Crypto::Hashes::SHA3_224.new
      result = sha3.hash("abc")
      result.should eq "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    end

    it "produces correct hash for longer message" do
      sha3 = Crypto::Hashes::SHA3_224.new
      result = sha3.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
      result.should eq "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
    end
  end

  describe "#output_size" do
    it "returns 28 bytes" do
      sha3 = Crypto::Hashes::SHA3_224.new
      sha3.output_size.should eq 28
    end
  end

  describe "#block_size" do
    it "returns 144 bytes" do
      sha3 = Crypto::Hashes::SHA3_224.new
      sha3.block_size.should eq 144
    end
  end
end

describe Crypto::Hashes::SHA3_256 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha3 = Crypto::Hashes::SHA3_256.new
      result = sha3.hash("")
      result.should eq "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    end

    it "produces correct hash for 'abc'" do
      sha3 = Crypto::Hashes::SHA3_256.new
      result = sha3.hash("abc")
      result.should eq "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    end

    it "produces correct hash for longer message" do
      sha3 = Crypto::Hashes::SHA3_256.new
      result = sha3.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
      result.should eq "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    end

    it "produces correct hash for binary data" do
      sha3 = Crypto::Hashes::SHA3_256.new
      input = Bytes[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
      result = sha3.hash_bytes(input).hexstring
      result.should eq "ed2479f84980d846cd12447f241059ac1679ac30584443d40222fb7e1639414c"
    end
  end

  describe "#hash_bytes" do
    it "produces correct bytes for 'abc'" do
      sha3 = Crypto::Hashes::SHA3_256.new
      result = sha3.hash_bytes("abc")
      expected = Bytes[
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
      ]
      result.should eq expected
    end
  end

  describe "#output_size" do
    it "returns 32 bytes" do
      sha3 = Crypto::Hashes::SHA3_256.new
      sha3.output_size.should eq 32
    end
  end

  describe "#block_size" do
    it "returns 136 bytes" do
      sha3 = Crypto::Hashes::SHA3_256.new
      sha3.block_size.should eq 136
    end
  end
end

describe Crypto::Hashes::SHA3_384 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha3 = Crypto::Hashes::SHA3_384.new
      result = sha3.hash("")
      result.should eq "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    end

    it "produces correct hash for 'abc'" do
      sha3 = Crypto::Hashes::SHA3_384.new
      result = sha3.hash("abc")
      result.should eq "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    end
  end

  describe "#output_size" do
    it "returns 48 bytes" do
      sha3 = Crypto::Hashes::SHA3_384.new
      sha3.output_size.should eq 48
    end
  end

  describe "#block_size" do
    it "returns 104 bytes" do
      sha3 = Crypto::Hashes::SHA3_384.new
      sha3.block_size.should eq 104
    end
  end
end

describe Crypto::Hashes::SHA3_512 do
  describe "#hash" do
    it "produces correct hash for empty string" do
      sha3 = Crypto::Hashes::SHA3_512.new
      result = sha3.hash("")
      result.should eq "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    end

    it "produces correct hash for 'abc'" do
      sha3 = Crypto::Hashes::SHA3_512.new
      result = sha3.hash("abc")
      result.should eq "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    end
  end

  describe "#output_size" do
    it "returns 64 bytes" do
      sha3 = Crypto::Hashes::SHA3_512.new
      sha3.output_size.should eq 64
    end
  end

  describe "#block_size" do
    it "returns 72 bytes" do
      sha3 = Crypto::Hashes::SHA3_512.new
      sha3.block_size.should eq 72
    end
  end
end