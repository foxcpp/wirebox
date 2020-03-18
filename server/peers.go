package wboxserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"

	"github.com/foxcpp/wirebox"
	"github.com/foxcpp/wirebox/linkmgr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func allocateDynamicIP(n *net.IPNet, poolOffset uint64, ipCounter uint64) (*IPAddr, error) {
	_, bits := n.Mask.Size()
	ipLen := bits / 8

	// Note: We do not skip statically assigned IPs. This is intentional to
	// keep it simple. "Pool offset" option should be used to prevent this
	// function from allocating certain IPs.
	ipCounter += poolOffset

	counterBytes := make([]byte, ipLen)
	if ipLen == 4 {
		if ipCounter >= math.MaxUint32 {
			return nil, errors.New("allocate dynamic: too many IPs for IPv4")
		}
		binary.BigEndian.PutUint32(counterBytes, uint32(ipCounter))
	} else {
		// Pad counter value by 8 bytes. Note: This does not support
		// allocation pool with prefix shorter than /64.
		binary.BigEndian.PutUint64(counterBytes[8:], ipCounter)
	}

	// Just OR ipCounter into node part of IP.
	var ip net.IP = make([]byte, ipLen)
	for i := range ip {
		ip[i] = n.IP[i] | counterBytes[i]
	}

	if !n.Contains(ip) {
		// ORing ipCounter changed the network prefix part of IP. We used up
		// entire allocation pool.
		return nil, errors.New("not enough IPs in a subnet")
	}
	if ipLen == 4 && ip[len(ip)-1] == 255 {
		// We cannot allocate the IPv4 broadcast address.
		return nil, errors.New("not enough IPs in a subnet")
	}

	return &IPAddr{Addr: ip, Net: n}, nil
}

func buildClientConfigs(cfg SrvConfig, clientKeys []wirebox.PeerKey) (map[wgtypes.Key]ClientCfg, error) {
	var (
		staticIPs  = len(cfg.Clients)
		dynamicIPs uint64
	)

	res := map[wgtypes.Key]ClientCfg{}
	for i, pubKey := range clientKeys {
		clCfg := cfg.Clients[pubKey.Encoded]

		if cfg.PtMP {
			clCfg.If = cfg.If
		} else if clCfg.If == "" {
			// We shift index by one make interface numbering consistent with
			// port numbers used (PortLow is used for configuration tunnel,
			// PortLow+1 for first client, etc).
			clCfg.If = cfg.If + "-c" + strconv.Itoa(i+1)
		}
		debugLog.Printf("using interface %v for %v", clCfg.If, pubKey)
		if clCfg.TunEndpoint4.Net == nil && clCfg.TunEndpoint6.Net == nil {
			clCfg.TunEndpoint4 = cfg.TunEndpoint4
			clCfg.TunEndpoint6 = cfg.TunEndpoint6
		}
		if cfg.PtMP {
			clCfg.TunPort = cfg.PortLow
		} else if clCfg.TunPort == 0 {
			clCfg.TunPort = cfg.PortLow + i + 1
			if clCfg.TunPort > cfg.PortHigh {
				log.Printf("ran out of UDP ports for tunnels! cannot allocate one for %v", pubKey)
			}
		}
		debugLog.Printf("using tunnel port %v for %v", clCfg.TunPort, pubKey)
		if len(clCfg.Addrs) == 0 {
			dynamicIPs++

			if cfg.Pool4.Net != nil {
				ipv4, err := allocateDynamicIP(cfg.Pool4.Net, cfg.Pool4Offset, dynamicIPs)
				if err != nil {
					log.Printf("ran out of dynamic IPv4s! cannot allocate one for %v: %v", pubKey, err)
				} else {
					clCfg.Addrs = append(clCfg.Addrs, *ipv4)
				}
				debugLog.Printf("dynamic IPv4 for %v: %v", pubKey, ipv4)
			}
			if cfg.Pool6.Net != nil {
				ipv6, err := allocateDynamicIP(cfg.Pool6.Net, cfg.Pool6Offset, dynamicIPs)
				if err != nil {
					log.Printf("ran out of dynamic IPv6s! cannot allocate one for %v: %v", pubKey, err)
				} else {
					clCfg.Addrs = append(clCfg.Addrs, *ipv6)
				}
				debugLog.Printf("dynamic IPv6 for %v: %v", pubKey, ipv6)
			}
		}
		if len(clCfg.Addrs) == 0 {
			log.Printf("no addresses for %v, node will be unable to connect", pubKey)
			continue
		}
		if len(clCfg.Routes) == 0 {
			clCfg.Routes = cfg.ClientRoutes
		}

		for _, a := range clCfg.Addrs {
			if a.Addr.To4() != nil && !cfg.Server4.PtP {
				a.Net = cfg.Server4.Net
			} else if !cfg.Server6.PtP {
				a.Net = cfg.Server6.Net
			}
		}

		res[pubKey.Bytes] = clCfg
	}

	log.Printf("created configurations for %v clients (%v static IPs, %v dynamic IPs)", uint64(staticIPs)+dynamicIPs, staticIPs, dynamicIPs)
	return res, nil
}

func configurePeerTuns(m linkmgr.Manager, cfg SrvConfig, clientKeys []wirebox.PeerKey, clientCfgs map[wgtypes.Key]ClientCfg) (allIfs, links []linkmgr.Link, err error) {
	allIfs = make([]linkmgr.Link, 0, len(clientKeys))
	links = make([]linkmgr.Link, 0, len(clientKeys))

	for _, pubKey := range clientKeys {
		clCfg, ok := clientCfgs[pubKey.Bytes]
		if !ok {
			continue
		}

		allowedIPs := make([]net.IPNet, 0, len(clCfg.Addrs))
		addrs := []linkmgr.Address{}
		for _, addr := range clCfg.Addrs {
			server := cfg.Server6.Addr
			if to4 := addr.Addr.To4(); to4 != nil {
				addr.Addr = to4
				server = cfg.Server4.Addr.To4()
			}
			_, bits := addr.Net.Mask.Size()

			allowedIPs = append(allowedIPs, net.IPNet{
				IP:   addr.Addr,
				Mask: net.CIDRMask(bits, bits),
			})
			addrs = append(addrs, linkmgr.Address{
				IPNet: net.IPNet{
					IP:   server,
					Mask: net.CIDRMask(bits, bits),
				},
				Peer: &net.IPNet{
					IP:   addr.Addr,
					Mask: net.CIDRMask(bits, bits),
				},
				Scope: linkmgr.ScopeGlobal,
			})
		}

		// Allow clients to renew configuration via configured tunnel.
		clientIPv6ll := wirebox.IPv6LLForClient(pubKey)
		allowedIPs = append(allowedIPs, net.IPNet{
			IP:   clientIPv6ll,
			Mask: net.CIDRMask(128, 128),
		})
		addrs = append(addrs, linkmgr.Address{
			IPNet: net.IPNet{
				IP:   wirebox.SolictIPv6,
				Mask: net.CIDRMask(128, 128),
			},
			Peer: &net.IPNet{
				IP:   clientIPv6ll,
				Mask: net.CIDRMask(128, 128),
			},
			Scope: linkmgr.ScopeLink,
		})

		iface, created, err := wirebox.CreateWG(m, clCfg.If, wgtypes.Config{
			PrivateKey:   &pubKey.Bytes,
			ReplacePeers: true,
			ListenPort:   &clCfg.TunPort,
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:  pubKey.Bytes,
					AllowedIPs: allowedIPs,
				},
			},
		}, addrs)
		if err != nil {
			for _, iface := range links {
				if err := m.DelLink(iface.Index()); err != nil {
					logErr(err)
				} else {
					log.Println("deleted link", iface.Name())
				}
			}

			return nil, nil, fmt.Errorf("peer tuns: %w", err)
		}
		allIfs = append(allIfs, iface)
		if created {
			log.Println("created link", clCfg.If, "for", pubKey)
			links = append(links, iface)
		} else {
			log.Println("using existing link", clCfg.If, "for", pubKey)
		}
	}

	return allIfs, links, nil
}
