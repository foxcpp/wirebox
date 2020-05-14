package linkmgr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ScopeGlobal AddrScope = unix.RT_SCOPE_UNIVERSE
	ScopeLink   AddrScope = unix.RT_SCOPE_LINK
)

var ErrNotWireguard = errors.New("named link is not a wireguard tunnel")

type LinkError struct {
	LinkName string
	E        error
}

func (err LinkError) Error() string {
	return fmt.Sprintf("link manager %s: %v", err.LinkName, err.E)
}

func (err LinkError) Unwrap() error {
	return err.E
}

type rtnLink struct {
	mngr  *rtnMngr
	iface net.Interface
}

func (l rtnLink) Interface() net.Interface {
	return l.iface
}

func (l rtnLink) Name() string {
	return l.iface.Name
}

func (l rtnLink) Index() int {
	return l.iface.Index
}

func (l rtnLink) ListenUDP(local net.UDPAddr) (*net.UDPConn, error) {
	// Apparentlty there is a weird race condition between link configuration
	// and binding that seems to disappear if index-based address zone is used.
	local.Zone = strconv.Itoa(l.iface.Index)
	return net.ListenUDP("udp", &local)
}

func (l rtnLink) DialUDP(local, remote net.UDPAddr) (*net.UDPConn, error) {
	// Apparentlty there is a weird race condition between link configuration
	// and binding that seems to disappear if index-based address zone is used.
	local.Zone = strconv.Itoa(l.iface.Index)
	remote.Zone = strconv.Itoa(l.iface.Index)

	localPtr := &local
	if localPtr.IP == nil {
		localPtr = nil
	}

	return net.DialUDP("udp", localPtr, &remote)
}

func (l rtnLink) SetUp(status bool) error {
	var flag uint32
	if status {
		flag = unix.IFF_UP
	}

	err := l.mngr.rtn.Link.Set(&rtnetlink.LinkMessage{
		Index:  uint32(l.iface.Index),
		Flags:  flag,
		Change: unix.IFF_UP,
	})
	if err != nil {
		return LinkError{l.iface.Name, err}
	}
	return nil
}

func (l rtnLink) IsUp() bool {
	link, err := l.mngr.rtn.Link.Get(uint32(l.iface.Index))
	if err != nil {
		return false
	}
	return link.Flags&unix.IFF_UP != 0
}

func asAddrMsg(ifaceIndx int, a Address) *rtnetlink.AddressMessage {
	var brd net.IP
	family := unix.AF_INET6
	if v4 := a.IP.To4(); v4 != nil {
		family = unix.AF_INET
		a.IP = v4
		if a.Peer != nil {
			a.Peer.IP = a.Peer.IP.To4()
		}

		brd = make(net.IP, 4)
		binary.BigEndian.PutUint32(brd, binary.BigEndian.Uint32(a.IP)|^binary.BigEndian.Uint32(net.IP(a.Mask).To4()))
	}

	prefixLen, _ := a.Mask.Size()

	local := a.IP
	iface := a.IP
	if a.Peer != nil {
		iface = a.Peer.IP
		prefixLen, _ = a.Peer.Mask.Size()
	}

	return &rtnetlink.AddressMessage{
		Family:       uint8(family),
		PrefixLength: uint8(prefixLen),
		Scope:        uint8(a.Scope),
		Index:        uint32(ifaceIndx),
		Attributes: rtnetlink.AddressAttributes{
			Address:   iface,
			Local:     local,
			Broadcast: brd,
		},
	}
}

func fromAddrMsg(m rtnetlink.AddressMessage) Address {
	cidrLen := 128
	if m.Family == unix.AF_INET {
		cidrLen = 32
	}

	a := Address{
		IPNet: net.IPNet{
			IP:   m.Attributes.Address,
			Mask: net.CIDRMask(int(m.PrefixLength), cidrLen),
		},
	}
	if !m.Attributes.Local.Equal(m.Attributes.Address) {
		a.Peer = &net.IPNet{
			IP:   m.Attributes.Local,
			Mask: net.CIDRMask(int(m.PrefixLength), cidrLen),
		}
	}

	return a
}

func (l rtnLink) AddAddr(a Address) error {
	err := l.mngr.rtn.Address.New(asAddrMsg(l.iface.Index, a))
	if err != nil {
		return LinkError{l.iface.Name, err}
	}
	return nil
}

func (l rtnLink) DelAddr(a Address) error {
	err := l.mngr.rtn.Address.Delete(asAddrMsg(l.iface.Index, a))
	if err != nil {
		return LinkError{l.iface.Name, err}
	}
	return nil
}

func (l rtnLink) Addrs() ([]Address, error) {
	msgs, err := l.mngr.rtn.Address.List()
	if err != nil {
		return nil, LinkError{l.iface.Name, err}
	}

	addrs := make([]Address, 0, len(msgs))
	for _, m := range msgs {
		if m.Index != uint32(l.iface.Index) {
			continue
		}
		addrs = append(addrs, fromAddrMsg(m))
	}
	return addrs, nil
}

func (l rtnLink) ConfigureWG(c wgtypes.Config) error {
	if err := l.mngr.wg.ConfigureDevice(l.iface.Name, c); err != nil {
		return LinkError{l.iface.Name, err}
	}
	return nil
}

func (l rtnLink) WGConfig() (*wgtypes.Device, error) {
	dev, err := l.mngr.wg.Device(l.iface.Name)
	if err != nil {
		return nil, LinkError{l.iface.Name, err}
	}
	return dev, nil
}

func asRouteMsg(ifaceIndx int, r Route) *rtnetlink.RouteMessage {
	family := unix.AF_INET6
	if v4 := r.Dest.IP; v4 != nil {
		family = unix.AF_INET
		r.Dest.IP = v4
		if r.Src != nil {
			r.Src = r.Src.To4()
			if r.Src == nil {
				panic("address type mismatch")
			}
		}
	}

	var srcLen uint8
	if r.Src != nil {
		srcLen = 128
		if family == unix.AF_INET {
			srcLen = 32
		}
	}

	dstLen, _ := r.Dest.Mask.Size()

	return &rtnetlink.RouteMessage{
		Family:    uint8(family),
		DstLength: uint8(dstLen),
		SrcLength: srcLen,
		Protocol:  RouteProto,
		Type:      unix.RTN_UNICAST,
		Attributes: rtnetlink.RouteAttributes{
			Dst:      r.Dest.IP,
			Src:      r.Src,
			OutIface: uint32(ifaceIndx),
		},
	}
}

func (l rtnLink) GetRoutes() ([]Route, error) {
	routes := []Route{}

	// get IPv4 routes
	routeMsgsInet, err := l.mngr.rtn.Route.List()
	if err != nil {
		return routes, LinkError{l.iface.Name, err}
	}
	for _, routeMsg := range routeMsgsInet {
		if routeMsg.Attributes.OutIface == uint32(l.iface.Index) && routeMsg.Attributes.Table == uint32(unix.RT_TABLE_MAIN) {
			maskLength := 32
			// if ip contains ":", it's IPv6
			if strings.Contains(routeMsg.Attributes.Dst.String(), ":") {
				maskLength = 128
			}
			routes = append(routes, Route{
				Dest: net.IPNet{IP: routeMsg.Attributes.Dst, Mask: net.CIDRMask(int(routeMsg.DstLength), maskLength)},
				Src:  routeMsg.Attributes.Src})
		}
	}

	return routes, nil
}

func (l rtnLink) AddRoute(r Route) error {
	err := l.mngr.rtn.Route.Add(asRouteMsg(l.iface.Index, r))
	if err != nil {
		return LinkError{l.iface.Name, err}
	}
	return nil
}

func (l rtnLink) DelRoute(r Route) error {
	err := l.mngr.rtn.Route.Delete(asRouteMsg(l.iface.Index, r))
	if err != nil {
		return LinkError{l.iface.Name, err}
	}
	return nil
}

var _ Link = rtnLink{}

type rtnMngr struct {
	rtn *rtnetlink.Conn
	wg  *wgctrl.Client
}

func fromLinkMsg(mngr *rtnMngr, m rtnetlink.LinkMessage) rtnLink {
	l := rtnLink{
		mngr: mngr,
		iface: net.Interface{
			Index:        int(m.Index),
			MTU:          int(m.Attributes.MTU),
			Name:         m.Attributes.Name,
			HardwareAddr: m.Attributes.Address,
		},
	}

	if m.Flags&unix.IFF_POINTOPOINT != 0 {
		l.iface.Flags |= net.FlagPointToPoint
	}
	if m.Flags&unix.IFF_MULTICAST != 0 {
		l.iface.Flags |= net.FlagMulticast
	}
	if m.Flags&unix.IFF_BROADCAST != 0 {
		l.iface.Flags |= net.FlagBroadcast
	}
	if m.Flags&unix.IFF_LOOPBACK != 0 {
		l.iface.Flags |= net.FlagLoopback
	}
	if m.Flags&unix.IFF_UP != 0 {
		l.iface.Flags |= net.FlagUp
	}

	return l
}

func (m *rtnMngr) Links() ([]Link, error) {
	msgs, err := m.rtn.Link.List()
	if err != nil {
		return nil, LinkError{"", err}
	}
	links := make([]Link, 0, len(msgs))
	for _, msg := range msgs {
		if msg.Attributes.Info == nil {
			continue
		}
		if msg.Attributes.Info.Kind != "wireguard" {
			continue
		}
		links = append(links, fromLinkMsg(m, msg))
	}
	return links, nil
}

func (m *rtnMngr) GetLink(name string) (Link, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, LinkError{name, err}
	}

	return rtnLink{m, *iface}, nil
}

func (m *rtnMngr) DelLink(indx int) error {
	if err := m.rtn.Link.Delete(uint32(indx)); err != nil {
		return LinkError{strconv.Itoa(indx), err}
	}
	return nil
}

func (m *rtnMngr) CreateLink(name string) (Link, error) {
	err := m.rtn.Link.New(&rtnetlink.LinkMessage{
		Type:  65534, // Seems to be set by 'ip link add' TODO: Why?
		Flags: unix.IFF_NOARP,
		Attributes: &rtnetlink.LinkAttributes{
			Name: name,
			Info: &rtnetlink.LinkInfo{
				Kind: "wireguard",
			},
		},
	})
	if err != nil {
		return nil, LinkError{name, err}
	}
	return m.GetLink(name)
}

func (m *rtnMngr) Close() error {
	m.rtn.Close()
	m.wg.Close()
	return nil
}

var _ Manager = &rtnMngr{}

func NewManager() (Manager, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("link mngr: %w", err)
	}

	rtn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("link mngr: %w", err)
	}
	return &rtnMngr{rtn: rtn, wg: wg}, nil
}
