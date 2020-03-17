package wboxproto

import (
	"encoding/binary"
	"net"
)

func (ipv6 *IPv6) AsIP() net.IP {
	if ipv6 == nil {
		return nil
	}
	res := make(net.IP, 16)
	binary.BigEndian.PutUint64(res[:8], ipv6.High)
	binary.BigEndian.PutUint64(res[8:], ipv6.Low)
	return res
}

func NewIPv6(addr net.IP) *IPv6 {
	if addr == nil {
		return nil
	}
	addr = addr.To16()
	return &IPv6{
		High: binary.BigEndian.Uint64(addr[:8]),
		Low:  binary.BigEndian.Uint64(addr[8:]),
	}
}

func IPv4(a uint32) net.IP {
	return net.IPv4(
		byte(a&0xFF000000>>24),
		byte(a&0x00FF0000>>16),
		byte(a&0x0000FF00>>8),
		byte(a&0x000000FF),
	)
}

func (n *Net4) AsIPNet() net.IPNet {
	return net.IPNet{
		IP:   IPv4(n.Addr),
		Mask: net.CIDRMask(int(n.PrefixLen), 32),
	}
}

func (n *Net6) AsIPNet() net.IPNet {
	return net.IPNet{
		IP:   n.Addr.AsIP(),
		Mask: net.CIDRMask(int(n.PrefixLen), 128),
	}
}
