package wboxserver

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/foxcpp/wirebox"
)

type SrvConfig struct {
	If   string `toml:"if"`
	PtMP bool   `toml:"ptmp"`

	PrivateKey wirebox.PeerKey `toml:"private-key"`
	Server4    IPAddr          `toml:"server4"`
	Server6    IPAddr          `toml:"server6"`

	TunEndpoint4 IPAddr `toml:"advertised-endpoint4"`
	TunEndpoint6 IPAddr `toml:"advertised-endpoint6"`

	PortLow  int `toml:"port-low"`
	PortHigh int `toml:"port-high"`

	// Network configuration for dynamically configured clients.
	Pool6        IPAddr  `toml:"pool6"`
	Pool6Offset  uint64  `toml:"pool6-offset"`
	Pool4        IPAddr  `toml:"pool4"`
	Pool4Offset  uint64  `toml:"pool4-offset"`
	ClientRoutes []Route `toml:"client_routes"`

	AuthFile string `toml:"authorized-keys"`

	// Overrides for static configuration. buildPool fills this map with for
	// dynamically configured clients. Keyed by base64-encoded client public
	// key.
	Clients map[string]ClientCfg `toml:"clients"`
}

func (c SrvConfig) Validate() error {
	if c.If == "" {
		return errors.New("config: if is required")
	}
	if len(c.If) > 15 {
		return errors.New("config: if is too long (can be 15 octets at most)")
	}
	if c.PrivateKey.Encoded == "" {
		return errors.New("config: private-key is required")
	}
	if c.Server4.Addr == nil && c.Server6.Addr == nil {
		return errors.New("config: at least one of server4, server6 is required")
	}
	if (c.PortLow == 0 && c.PortHigh != 0) || (c.PortHigh != 0 && c.PortLow == 0) {
		return errors.New("config: both or none of port-low and port-high should be specified")
	}
	if c.PortLow != 0 && c.PortHigh != 0 {
		if c.PortLow >= c.PortHigh {
			return errors.New("config: port range should contain at least two ports")
		}
		if c.PortLow < 0 || c.PortLow > 65535 {
			return errors.New("config: invalid port-low")
		}
		if c.PortHigh < 0 || c.PortHigh > 65535 {
			return errors.New("config: invalid port-high")
		}
	}

	if c.Pool6.Addr != nil && c.Server6.Addr == nil {
		return errors.New("config: server6 is required if pool6 is used")
	}
	if c.Pool4.Addr != nil && c.Server4.Addr == nil {
		return errors.New("config: server4 is required if pool4 is used")
	}
	if c.AuthFile == "" && len(c.Clients) == 0 {
		return errors.New("config: at least one of authorized-keys, clients is required")
	}

	for pubKey, clCfg := range c.Clients {
		if len(clCfg.Addrs) == 0 && (c.Pool6.Addr == nil && c.Pool4.Addr == nil) {
			return errors.New("config: missing addresses for " + pubKey)
		}
		if clCfg.TunPort == 0 && c.PortLow == 0 {
			return errors.New("config: missing tunnel port (or shared port range) for " + pubKey)
		}
		if len(clCfg.If) > 15 {
			return errors.New("config: too long interface name for " + pubKey)
		}
	}

	return nil
}

type ClientCfg struct {
	TunPort      int    `toml:"tun-port"`
	TunEndpoint4 IPAddr `toml:"tun-endpoint4"`
	TunEndpoint6 IPAddr `toml:"tun-endpoint6"`

	If string `toml:"if"`

	Addrs  []IPAddr `toml:"addrs"`
	Routes []Route  `toml:"client_routes"`
}

type Route struct {
	Src  *IPAddr `toml:"src"`
	Dest *IPAddr `toml:"dest"`
}

type IPAddr struct {
	Addr net.IP
	Net  *net.IPNet
}

func (a *IPAddr) String() string {
	prefixLen, _ := a.Net.Mask.Size()
	return fmt.Sprintf("%v/%v", a.Addr, prefixLen)
}

func (a *IPAddr) UnmarshalText(text []byte) error {
	addr := string(text)

	if strings.Contains(addr, "/") {
		var err error
		a.Addr, a.Net, err = net.ParseCIDR(addr)
		return err
	}

	// If no prefix length was specified - assume the peer-to-peer
	// configuration is desired.
	a.Addr = net.ParseIP(addr)
	if a.Addr == nil {
		return errors.New("malformed IP")
	}

	// Build dummy value for IPNet that covers only specified IP.
	prefixLen := 128
	if a.Addr.To4() != nil {
		prefixLen = 32
	}

	a.Net = &net.IPNet{
		IP:   a.Addr,
		Mask: net.CIDRMask(prefixLen, prefixLen),
	}
	return nil
}
