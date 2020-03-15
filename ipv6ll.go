package wirebox

import (
	"math/big"
	"net"
)

// IPv6LLForClient generates the IPv6 link-local client will use for
// negotiation on the configuration tunnel.
//
// It is determistic and based on the client public key. However, it does not
// authenticate the client in any way and nor is collision-safe since it
// coerces 256-bit key into 128-bit IPv6 address with two reserved bytes.
//
// Determistic assignment is needed for tunnel configuration at the server
// side. WG's "Allowed IPs" cannot say "any IP" for mulitple peers on the same
// interface.
func IPv6LLForClient(publicKey PeerKey) net.IP {
	i := &big.Int{}
	i.SetBytes(publicKey.Bytes[:])

	i112 := big.NewInt(2)
	i112.Lsh(i112, 112)
	i.Mul(i, i112)

	i256 := big.NewInt(2)
	i256.Lsh(i256, 256)
	i.Div(i, i256)

	res := net.ParseIP("fe80::")
	for i, b := range i.Bytes() {
		res[i+2] = b
	}
	return res
}
