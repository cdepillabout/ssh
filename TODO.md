
# TODO

- write tests in this order:

    1. SSH/Crypto.hs
    1. SSH/Sender.hs
    1. SSH/Channel.hs
    1. SSH/Session.hs
    1. SSH.hs

- In `SSH/Internal/Util.hs`, `fromOctet` and `toOctet` take a base argument, but
  everywhere they are used, it is just being passed as 256, so really we
  should just hard-code 256 into the method.

- Do tests/documentation for `makeKey` from `SSH/Packet.hs`.

- Things like the KeyPair data type should be fixed so that an RSAKeyPair can't be instantiated with something like a DSAPublicKey.
