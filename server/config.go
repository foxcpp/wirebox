package wboxserver

import (
	"errors"
	"fmt"
	"net"

	"github.com/foxcpp/wirebox"
)

type SrvConfig struct {
	If   string `toml:"if"`
	PtMP bool   `toml:"ptmp"`

	Subnet4 IPNet `toml:"subnet4"`
	Subnet6 IPNet `toml:"subnet6"`

	PrivateKey wirebox.PeerKey `toml:"private-key"`
	Server4    IPAddr          `toml:"server4"`
	Server6    IPAddr          `toml:"server6"`

	TunEndpoint4 IPAddr `toml:"advertised-endpoint4"`
	TunEndpoint6 IPAddr `toml:"advertised-endpoint6"`

	PortLow  int `toml:"port-low"`
	PortHigh int `toml:"port-high"`

	// Network configuration for dynamically configured clients.
	Pool6        IPNet   `toml:"pool6"`
	Pool6Offset  uint64  `toml:"pool6-offset"`
	Pool4        IPNet   `toml:"pool4"`
	Pool4Offset  uint64  `toml:"pool4-offset"`
	ClientRoutes []Route `toml:"client-routes"`

	AuthFile string `toml:"authorized-keys"`

	// Overrides for static configuration.
	Clients map[string]ClientOverrides `toml:"clients"`
}

func (c SrvConfig) Validate() error {
	if c.If == "" {
		return errors.New("config: if is required")
	}
	if c.PtMP && len(c.If) > 15 {
		return errors.New("config: if is too long (can be 15 octets at most)")
	}
	if !c.PtMP && len(c.If) > 12 {
		return errors.New("config: if is too long (can be 15 octets at most, including client sequence number)")
	}

	if c.PrivateKey.Encoded == "" {
		return errors.New("config: private-key is required")
	}
	if c.Server4.IP == nil && c.Server6.IP == nil {
		return errors.New("config: at least one of server4, server6 is required")
	}
	if (c.PortLow == 0 && c.PortHigh != 0) || (c.PortHigh != 0 && c.PortLow == 0) {
		return errors.New("config: both or none of port-low and port-high should be specified")
	}
	if c.PortLow != 0 && c.PortHigh != 0 {
		if !c.PtMP && c.PortLow >= c.PortHigh {
			return errors.New("config: port range should contain at least two ports")
		}
		if c.PortLow < 0 || c.PortLow > 65535 {
			return errors.New("config: invalid port-low")
		}
		if c.PortHigh < 0 || c.PortHigh > 65535 {
			return errors.New("config: invalid port-high")
		}
	}
	if c.PtMP && c.PortHigh-c.PortLow != 0 {
		return errors.New("config: ports other than port-low are not used in PtMP mode")
	}

	if (c.Pool6.IP != nil || c.Subnet6.IP == nil) && c.Server6.IP == nil {
		return errors.New("config: server6 is required if pool6 or subnet6 is used")
	}
	if (c.Pool4.IP != nil || c.Subnet4.IP == nil) && c.Server4.IP == nil {
		return errors.New("config: server4 is required if pool4 or subnet4 is used")
	}
	if c.AuthFile == "" && len(c.Clients) == 0 {
		return errors.New("config: at least one of authorized-keys, clients is required")
	}

	for pubKey, clCfg := range c.Clients {
		if len(clCfg.Addrs) == 0 && (c.Pool6.IP == nil && c.Pool4.IP == nil) {
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

type ClientOverrides struct {
	TunPort      int    `toml:"tun-port"`
	TunEndpoint4 IPAddr `toml:"tun-endpoint4"`
	TunEndpoint6 IPAddr `toml:"tun-endpoint6"`

	If string `toml:"if"`

	Addrs  []IPAddr `toml:"addrs"`
	Routes []Route  `toml:"client_routes"`
}

type Route struct {
	Src  *IPNet `toml:"src"`
	Dest *IPNet `toml:"dest"`
}

type IPAddr struct {
	net.IP
}

func (a IPAddr) String() string {
	return a.IP.String()
}

func (a *IPAddr) UnmarshalText(text []byte) error {
	addr := string(text)

	a.IP = net.ParseIP(addr)
	if a.IP == nil {
		return errors.New("malformed IP")
	}

	return nil
}

type IPNet struct {
	net.IPNet
}

func (a IPNet) String() string {
	prefixLen, _ := a.Mask.Size()
	return fmt.Sprintf("%v/%v", a.IP, prefixLen)
}

func (a *IPNet) UnmarshalText(text []byte) error {
	addr := string(text)

	_, network, err := net.ParseCIDR(addr)
	a.IP = network.IP
	a.Mask = network.Mask
	return err
}
