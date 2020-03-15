# WireGuard Dynamic Configuration Protocol (WGDCP)
Protocol version: 1

## Goals

- Centralize the tunnel configuration
  Make client configuration unimportant, server is a single "source of truth"
  for information about IPs and routes to be used.
- Provide simplified configuration for nodes that do not need a stable IP
- Rely on Linux kernel mechanisms as much as possible
  To minimize client and server complexity. Important implication: We create an
  interface per peer on the server side so we could reuse kernel multicast
  router.
- Keep amount of RTTs needed to estabsilish a working tunnel low WireGuard is
  extremely light on traffic, we do not want to ruin it.

## Wire format

Communication happens over UDP protocol using Google's Protocol Buffers for
message serialization with lightweight framing to determine message type and
protocol versioning. Each datagram has following in its payload:
- Unsigned 1-byte integer, protocol version
  Indicates protocol version implemented by the sender and used in this message.
  Server SHOULD provide support for older versions for a reasonable period of
  time and SHOULD use protocol version used by the connected client. If server
  does not support the requested version - NACK message should
  be sent using special protocol version "0".
- Unsigned 1-byte integer, message type
  Indicates the type of the following message. See protocol.proto for
  assignments.
- Protocol Buffer-serialized message contents

At the moment, entire payload is limited in size to 1380 octets to prevent
complexities of fragmentation.

## Network configuration flow

For protocol to work correctly, sides need to have following information
obtained and configured via out-of-band means:

Client:
- Solication tunnel endpoint (IP address and UDP port number)
- Server public key
- Client public key & private key

Server:
- Solictation tunnel endpoint configured to match one used by clients
- Public key of each client


