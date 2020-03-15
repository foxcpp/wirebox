package wboxclient

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/foxcpp/wirebox"
	wboxproto "github.com/foxcpp/wirebox/proto"
	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func configureTunnel(cfg Config) error {
	log.Println("configuring tunnel")
	pubKey := cfg.PrivateKey.PublicFromPrivate()
	configIPv6 := wirebox.IPv6LLForClient(pubKey)

	tunIf, created, err := createConfigTun(cfg, configIPv6)
	if err != nil {
		return fmt.Errorf("configure tun: %w", err)
	}

	clCfg, err := solictCfg(cfg, configIPv6, pubKey, tunIf)
	if err != nil {
		if created {
			if err := wirebox.Conn.Link.Delete(uint32(tunIf.Index)); err != nil {
				log.Println("error: failed to delete link:", err)
			}
		}
		return fmt.Errorf("configure tun: %w", err)
	}

	if err := setTunnelCfg(cfg, tunIf, configIPv6, clCfg); err != nil {
		if created {
			if err := wirebox.Conn.Link.Delete(uint32(tunIf.Index)); err != nil {
				log.Println("error: failed to delete link:", err)
			}
		}
		return fmt.Errorf("configure tun: %w", err)
	}
	return nil
}

func setTunnelCfg(cfg Config, tunIf *net.Interface, configIPv6 net.IP, clCfg *wboxproto.Cfg) error {
	wgCfg := wgtypes.Config{
		PrivateKey: &cfg.PrivateKey.Bytes,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         cfg.ServerKey.Bytes,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					{
						IP:   wirebox.SolictIPv6,
						Mask: net.CIDRMask(128, 128),
					},
					{
						IP:   configIPv6,
						Mask: net.CIDRMask(128, 128),
					},
				},
			},
		},
	}

	srvEndpoint := cfg.ConfigEndpoint
	if port := clCfg.GetTunPort(); port != 0 {
		srvEndpoint.Port = int(port)
	}
	if endp := clCfg.GetTun4Endpoint(); endp != 0 {
		srvEndpoint.IP = wboxproto.IPv4(clCfg.GetTun4Endpoint())
	}
	if endp := clCfg.GetTun6Endpoint(); endp != nil {
		srvEndpoint.IP = clCfg.GetTun6Endpoint().AsIP()
	}
	// TODO: Test IPv6 connectivity and do not attempt to use it?
	log.Printf("tunnel via %v:%v", srvEndpoint.IP, srvEndpoint.Port)

	var addrs []rtnetlink.AddressMessage
	for _, net6 := range clCfg.Net6 {
		wgCfg.Peers[0].AllowedIPs = append(wgCfg.Peers[0].AllowedIPs, net.IPNet{
			IP:   net6.GetAddr().AsIP(),
			Mask: net.CIDRMask(int(net6.GetPrefixLen()), 128),
		})

		log.Printf("using addr %v/%v", net6.Addr.AsIP(), net6.PrefixLen)
		addrs = append(addrs, rtnetlink.AddressMessage{
			Family:       unix.AF_INET6,
			PrefixLength: uint8(net6.GetPrefixLen()),
			Flags:        unix.IFA_F_PERMANENT,
			Scope:        unix.RT_SCOPE_UNIVERSE,
			Attributes: rtnetlink.AddressAttributes{
				Address: net6.Addr.AsIP(),
				Local:   net6.Addr.AsIP(),
			},
		})
	}
	for _, net4 := range clCfg.Net4 {
		ip := wboxproto.IPv4(net4.GetAddr()).To4()
		mask := net.CIDRMask(int(net4.GetPrefixLen()), 32)
		wgCfg.Peers[0].AllowedIPs = append(wgCfg.Peers[0].AllowedIPs, net.IPNet{
			IP:   ip,
			Mask: mask,
		})

		var brd net.IP
		brd = make(net.IP, 4)
		binary.BigEndian.PutUint32(brd, binary.BigEndian.Uint32(ip)|^binary.BigEndian.Uint32(net.IP(mask).To4()))

		log.Printf("using addr %v/%v", wboxproto.IPv4(net4.Addr), net4.PrefixLen)
		addrs = append(addrs, rtnetlink.AddressMessage{
			Family:       unix.AF_INET,
			PrefixLength: uint8(net4.GetPrefixLen()),
			Scope:        unix.RT_SCOPE_UNIVERSE,
			Attributes: rtnetlink.AddressAttributes{
				Address:   ip,
				Local:     ip,
				Broadcast: brd,
			},
		})
	}

	for _, route4 := range clCfg.Routes4 {
		log.Printf("using route %v/%v via %v src %v",
			wboxproto.IPv4(route4.Dest.Addr), route4.Dest.PrefixLen,
			wboxproto.IPv4(route4.Gateway),
			wboxproto.IPv4(route4.Src))
		wgCfg.Peers[0].AllowedIPs = append(wgCfg.Peers[0].AllowedIPs, net.IPNet{
			IP:   wboxproto.IPv4(route4.GetDest().Addr),
			Mask: net.CIDRMask(int(route4.GetDest().GetPrefixLen()), 32),
		})
	}
	for _, route6 := range clCfg.Routes6 {
		log.Printf("using route %v/%v via %v src %v",
			route6.Dest.Addr.AsIP(), route6.Dest.PrefixLen,
			route6.Gateway.AsIP(),
			route6.Src.AsIP())
		wgCfg.Peers[0].AllowedIPs = append(wgCfg.Peers[0].AllowedIPs, net.IPNet{
			IP:   route6.GetDest().Addr.AsIP(),
			Mask: net.CIDRMask(int(route6.GetDest().GetPrefixLen()), 128),
		})
	}

	tunIf, _, err := wirebox.CreateWG(cfg.If, wgCfg, addrs)
	if err != nil {
		return fmt.Errorf("set config: %w", err)
	}
	log.Println("tunnel reconfigured")

	for i, route4 := range clCfg.Routes4 {
		msg := &rtnetlink.RouteMessage{
			Family:    unix.AF_INET,
			DstLength: uint8(route4.GetDest().GetPrefixLen()),
			SrcLength: 32,
			Protocol:  wirebox.RouteProto,
			Attributes: rtnetlink.RouteAttributes{
				Dst:      wboxproto.IPv4(route4.GetDest().Addr),
				OutIface: uint32(tunIf.Index),
			},
		}
		if route4.GetSrc() != 0 {
			msg.Attributes.Src = wboxproto.IPv4(route4.GetSrc())
		}
		if route4.GetGateway() != 0 {
			msg.Attributes.Gateway = wboxproto.IPv4(route4.GetGateway())
		}
		if err := wirebox.Conn.Route.Add(msg); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return fmt.Errorf("set config: route4 add %v: %w", i, err)
		}
	}
	log.Println("installed IPv4 routes")

	for i, route6 := range clCfg.Routes6 {
		msg := &rtnetlink.RouteMessage{
			Family:    unix.AF_INET6,
			DstLength: uint8(route6.GetDest().GetPrefixLen()),
			SrcLength: 128,
			Protocol:  wirebox.RouteProto,
			Attributes: rtnetlink.RouteAttributes{
				Dst:      route6.GetDest().Addr.AsIP(),
				OutIface: uint32(tunIf.Index),
			},
		}
		if route6.GetSrc() != nil {
			msg.Attributes.Src = route6.GetSrc().AsIP()
		}
		if route6.GetGateway() != nil {
			msg.Attributes.Gateway = route6.GetGateway().AsIP()
		}
		if err := wirebox.Conn.Route.Add(msg); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return fmt.Errorf("set config: route6 add %v: %w", i, err)
		}
	}
	log.Println("installed IPv6 routes")

	return nil
}

func createConfigTun(cfg Config, configIPv6 net.IP) (*net.Interface, bool, error) {
	tunIf, created, err := wirebox.CreateWG(cfg.If, wgtypes.Config{
		PrivateKey: &cfg.PrivateKey.Bytes,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: cfg.ServerKey.Bytes,
				Endpoint:  &cfg.ConfigEndpoint.UDPAddr,
				// ReplaceAllowedIPs: false
				//  We want to permit regular traffic while we attempt tunnel
				//  reconfiguration.
				AllowedIPs: []net.IPNet{
					{
						IP:   wirebox.SolictIPv6,
						Mask: net.CIDRMask(128, 128),
					},
					{
						IP:   configIPv6,
						Mask: net.CIDRMask(128, 128),
					},
				},
			},
		},
	}, []rtnetlink.AddressMessage{
		{
			Family:       unix.AF_INET6,
			PrefixLength: 128,
			Flags:        unix.IFA_F_PERMANENT,
			Scope:        unix.RT_SCOPE_LINK,
			Attributes: rtnetlink.AddressAttributes{
				Address: wirebox.SolictIPv6,
				Local:   configIPv6,
			},
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("create config tun: %w", err)
	}
	if created {
		log.Println("created link", tunIf.Name)
	} else {
		log.Println("using existing link", tunIf.Name)
	}
	return tunIf, created, nil
}

func solictCfg(cfg Config, configIPv6 net.IP, pubKey wirebox.PeerKey, tunIf *net.Interface) (*wboxproto.Cfg, error) {
	c, err := net.DialUDP("udp6", &net.UDPAddr{
		IP:   configIPv6,
		Zone: strconv.Itoa(tunIf.Index),
	}, &net.UDPAddr{
		IP:   wirebox.SolictIPv6,
		Port: wirebox.SolictPort,
		// Apparently, using interface index of name fixes the race (?) that
		// makes interface unusable for the process just after its
		// configuration.
		Zone: strconv.Itoa(tunIf.Index),
	})
	if err != nil {
		return nil, fmt.Errorf("solict cfg: %w", err)
	}
	defer c.Close()

	for {
		log.Println("solicting configuration")
		solictMsg, err := wboxproto.Pack(&wboxproto.CfgSolict{
			PeerPubkey: pubKey.Bytes[:],
		})
		if err != nil {
			return nil, fmt.Errorf("solict cfg: %w", err)
		}
		if _, err := c.Write(solictMsg); err != nil {
			// We can get ICMP errors reported at the next Write. Stop if we got ICMP "No route to host",
			// "Port unreachable" (EREFUSED) or whatever.
			return nil, fmt.Errorf("solict cfg: %w", err)
		}

		if err := c.SetReadDeadline(time.Now().Add(cfg.ConfigTimeout.Duration)); err != nil {
			log.Println("error: cannot set timeout, configuration may hang:", err)
		}

		buffer := make([]byte, 1420)
		readBytes, sender, err := c.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				log.Println("timed out waiting for response, retrying")
				continue
			}
			return nil, fmt.Errorf("solict cfg: %w", err)
		}

		if !sender.IP.Equal(wirebox.SolictIPv6) {
			return nil, fmt.Errorf("solict cfg: unexpected response sender %v", sender.IP)
		}
		if sender.Port != wirebox.SolictPort {
			return nil, fmt.Errorf("solict cfg: unexpected response source port %v", sender.Port)
		}

		resp, err := wboxproto.Unpack(buffer[:readBytes])
		if err != nil {
			log.Println("malformed response, retrying:", err)
			continue
		}
		switch resp := resp.(type) {
		case *wboxproto.Cfg:
			return resp, nil
		case *wboxproto.Nack:
			return nil, fmt.Errorf("solict cfg: server refused to give us config: %v", resp.GetDescription())
		default:
			return nil, fmt.Errorf("solict cfg: unexpected reply: %T", resp)
		}
	}
}

func Main() int {
	// Read configuration and command line flags.
	cfgPath := flag.String("config", "wbox.toml", "path to configuration file")
	flag.Parse()
	cfgF, err := os.Open(*cfgPath)
	if err != nil {
		log.Println("error:", err)
		return 2
	}
	var cfg Config
	if _, err := toml.DecodeReader(cfgF, &cfg); err != nil {
		log.Println("error: config load:", err)
		return 2
	}
	if cfg.ConfigTimeout.Duration == 0 {
		cfg.ConfigTimeout.Duration = 5 * time.Second
	}

	log.Println("client public key:", cfg.PrivateKey.PublicFromPrivate())

	if err := configureTunnel(cfg); err != nil {
		log.Println("error:", err)
		return 1
	}

	return 0
}
