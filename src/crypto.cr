require "./crypto/*"
require "./crypto/algorithms/*"

# TODO: Write documentation for `Crypto`
module Crypto
  # TODO: Put your code here
end

hash = Crypto::Algorithms::SCrypt.hash("", "", n: 4)
puts hash.hexstring
