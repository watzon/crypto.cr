module Crypto::Algorithms
  abstract class HashAlgorithm

    # getter :multiplier

    abstract def hash(input : String)

  end
end
