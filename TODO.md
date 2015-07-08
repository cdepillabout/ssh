
# TODO

- write tests in this order:

    1. SSH/Sender.hs
    1. SSH/Channel.hs
    1. SSH/Session.hs
    1. SSH.hs

- In `SSH/Internal/Util.hs`, `fromOctet` and `toOctet` take a base argument,
  but everywhere they are used, it is just being passed as 256, so really we
  should just hard-code 256 into the method.

- Do tests/documentation for `makeKey` from `SSH/Packet.hs`.

- Things like the KeyPair data type should be fixed so that an RSAKeyPair can't
  be instantiated with something like a DSAPublicKey.

- Add interesting things from SSH rfc to documentation:

    * Message numbers for things from transport layer protocol, user
      authentication protocol, and connection protocol differ.

      [rfc4251](http://tools.ietf.org/html/rfc4251#section-7)

    * Explanation of different layers of SSH.  Secure Shell (SSH) is a protocol
      for secure remote login and other secure network services over an
      insecure network.  It consists of three major components:

        - The [Transport Layer Protocol](http://tools.ietf.org/html/rfc4253)
          provides server authentication, confidentiality, and integrity.  It
          may optionally also provide compression.  The transport layer will
          typically be run over a TCP/IP connection, but might also be used on
          top of any other reliable data stream.

          The transport protocol provides a confidential channel over an
          insecure network.  It performs server host authentication, key
          exchange, encryption, and integrity protection.  It also derives a
          unique session id that may be used by higher-level protocols.

        - The [User Authentication
          Protocol](http://tools.ietf.org/html/rfc4252) authenticates the
          client-side user to the server.  It runs over the transport layer
          protocol.

          The authentication protocol provides a suite of mechanisms that can
          be used to authenticate the client user to the server.  Individual
          mechanisms specified in the authentication protocol use the session
          id provided by the transport protocol and/or depend on the security
          and integrity guarantees of the transport protocol.

        - The [Connection Protocol](http://tools.ietf.org/html/rfc4254)
          multiplexes the encrypted tunnel into several logical channels.  It
          runs over the user authentication protocol.

          The connection protocol specifies a mechanism to multiplex multiple
          streams (channels) of data over the confidential and authenticated
          transport.  It also specifies channels for accessing an interactive
          shell, for proxy-forwarding various external protocols over the
          secure transport (including arbitrary TCP/IP protocols), and for
          accessing secure subsystems on the server host.


