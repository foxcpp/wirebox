package linkmgr

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type AddrScope int

type Address struct {
	net.IPNet
	Peer  *net.IPNet
	Scope AddrScope
}

type Route struct {
	Dest net.IPNet
	Src  net.IP
}

type Link interface {
	Interface() net.Interface
	Name() string
	Index() int

	IsUp() bool
	SetUp(bool) error
	Addrs() ([]Address, error)
	DelAddr(a Address) error
	AddAddr(a Address) error

	ConfigureWG(wgtypes.Config) error
	WGConfig() (*wgtypes.Device, error)

	DialUDP(local, remote net.UDPAddr) (*net.UDPConn, error)
	ListenUDP(local net.UDPAddr) (*net.UDPConn, error)

	AddRoute(Route) error
	DelRoute(Route) error
}

type Manager interface {
	Links() ([]Link, error)
	CreateLink(name string) (Link, error)
	DelLink(indx int) error
	GetLink(name string) (Link, error)

	Close() error
}

const (
	RouteProto = 157
)
