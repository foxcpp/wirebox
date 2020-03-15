package wboxclient

import (
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/foxcpp/wirebox"
)

type Config struct {
	If         string          `toml:"if"`
	PrivateKey wirebox.PeerKey `toml:"private-key"`

	ServerKey      wirebox.PeerKey `toml:"server-key"`
	ConfigEndpoint UDPAddr         `toml:"config-endpoint"`

	ConfigTimeout Duration `toml:"config-timeout"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

type UDPAddr struct {
	net.UDPAddr
}

func (a *UDPAddr) UnmarshalText(text []byte) error {
	host, port, err := net.SplitHostPort(string(text))
	if err != nil {
		return err
	}

	a.UDPAddr.IP = net.ParseIP(host)
	if a.IP == nil {
		return errors.New("malformed IP")
	}
	a.Port, err = strconv.Atoi(port)
	if err != nil {
		return err
	}
	return nil
}

type IPAddr struct {
	net.IP
}

func (a *IPAddr) UnmarshalText(text []byte) error {
	a.IP = net.ParseIP(string(text))
	if a.IP == nil {
		return errors.New("malformed IP")
	}
	return nil
}
