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

type ClientCfg struct {
	ServerIf string

	TunEndpoint4 net.IP
	TunEndpoint6 net.IP
	TunPort      int

	Addrs  []net.IPNet
	Routes []Route
}

func allocateDynamicIP(poolNet *net.IPNet, poolOffset uint64, ipCounter uint64) (net.IP, error) {
	_, bits := poolNet.Mask.Size()
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
		ip[i] = poolNet.IP[i] | counterBytes[i]
	}

	if !poolNet.Contains(ip) {
		// ORing ipCounter changed the network prefix part of IP. We used up
		// entire allocation pool.
		return nil, errors.New("not enough IPs in a pool subnet")
	}
	if ipLen == 4 && ip[len(ip)-1] == 255 {
		// We cannot allocate the IPv4 broadcast address.
		return nil, errors.New("not enough IPs in a pool subnet")
	}

	return ip, nil
}

func buildClientConfigs(cfg SrvConfig, clientKeys []wirebox.PeerKey) (map[wgtypes.Key]ClientCfg, error) {
	var (
		staticIPs  = len(cfg.Clients)
		dynamicIPs uint64
	)

	res := map[wgtypes.Key]ClientCfg{}
	for i, pubKey := range clientKeys {
		overrides := cfg.Clients[pubKey.Encoded]
		clCfg := ClientCfg{
			TunEndpoint4: overrides.TunEndpoint4.IP,
			TunEndpoint6: overrides.TunEndpoint6.IP,
			TunPort:      overrides.TunPort,
		}

		// Set interface name to be used on the server side. If we are creating
		// per-client interfaces - generate it in form "CONFIG_IF-cXXX".
		if cfg.PtMP {
			clCfg.ServerIf = cfg.If
		} else if overrides.If == "" {
			// We shift index by one make interface numbering consistent with
			// port numbers used (PortLow is used for configuration tunnel,
			// PortLow+1 for first client, etc).
			clCfg.ServerIf = cfg.If + "-c" + strconv.Itoa(i+1)
		}
		debugLog.Printf("using interface %v for %v", overrides.If, pubKey)

		// Override tunnel UDP endpoint to be used by the client. Aka "tunnel
		// redirect".
		if clCfg.TunEndpoint4 == nil && clCfg.TunEndpoint6 == nil {
			clCfg.TunEndpoint4 = cfg.TunEndpoint4.IP
			clCfg.TunEndpoint6 = cfg.TunEndpoint6.IP
		}

		// Set tunnel port to be used by the client
		if cfg.PtMP {
			clCfg.TunPort = cfg.PortLow
		}
		if clCfg.TunPort == 0 {
			clCfg.TunPort = cfg.PortLow + i + 1
			if clCfg.TunPort > cfg.PortHigh {
				log.Printf("ran out of UDP ports for tunnels! cannot allocate one for %v", pubKey)
				continue
			}
		}
		debugLog.Printf("using tunnel port %v for %v", clCfg.TunPort, pubKey)

		// If we have no static IPs for the client - assign some dynamically.
		if len(overrides.Addrs) == 0 {
			dynamicIPs++

			if cfg.Pool4.IP != nil {
				ipv4, err := allocateDynamicIP(&cfg.Pool4.IPNet, cfg.Pool4Offset, dynamicIPs)
				if err != nil {
					log.Printf("ran out of dynamic IPv4s! cannot allocate one for %v: %v", pubKey, err)
				} else {
					overrides.Addrs = append(overrides.Addrs, IPAddr{ipv4})
				}
				debugLog.Printf("dynamic IPv4 for %v: %v", pubKey, ipv4)
			}
			if cfg.Pool6.IP != nil {
				ipv6, err := allocateDynamicIP(&cfg.Pool6.IPNet, cfg.Pool6Offset, dynamicIPs)
				if err != nil {
					log.Printf("ran out of dynamic IPv6s! cannot allocate one for %v: %v", pubKey, err)
				} else {
					overrides.Addrs = append(overrides.Addrs, IPAddr{ipv6})
				}
				debugLog.Printf("dynamic IPv6 for %v: %v", pubKey, ipv6)
			}
		}

		// Generate IPv4/IPv6 address assignments to be used by the client.
		// If Subnet4/6 is used - use its prefix with allocated address.
		// Otherwise use /128, client will add the explicit route for the
		// server address.
		for _, a := range overrides.Addrs {
			subnet := cfg.Subnet6
			maskLen := 128
			if a.To4() != nil {
				subnet = cfg.Subnet4
				maskLen = 32
			}

			if subnet.IP == nil {
				clCfg.Addrs = append(clCfg.Addrs, net.IPNet{
					IP:   a.IP,
					Mask: net.CIDRMask(maskLen, maskLen),
				})
			} else {
				if !subnet.Contains(a.IP) {
					log.Printf("WARNING: %v is not in %v network, this *will not* work correctly, ignoring assignment for %v", a.IP, subnet, pubKey)
					continue
				}
				clCfg.Addrs = append(clCfg.Addrs, net.IPNet{
					IP:   a.IP,
					Mask: subnet.Mask,
				})
			}
		}
		if len(clCfg.Addrs) == 0 {
			log.Printf("no addresses for %v, node will be unable to connect", pubKey)
			continue
		}

		clCfg.Routes = overrides.Routes
		if len(clCfg.Routes) == 0 {
			clCfg.Routes = cfg.ClientRoutes
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

		// Prepare addresses assignments for per-client interfaces. For PtP
		// interface mode, this is always "local SERVER peer CLIENT/128".
		addrs := []linkmgr.Address{}
		for _, addr := range clCfg.Addrs {
			server := cfg.Server6.IP
			if to4 := addr.IP.To4(); to4 != nil {
				addr.IP = to4
				server = cfg.Server4.To4()
			}
			_, maskLen := addr.Mask.Size()

			addrs = append(addrs, linkmgr.Address{
				IPNet: net.IPNet{
					IP:   server,
					Mask: net.CIDRMask(maskLen, maskLen),
				},
				Peer: &net.IPNet{
					IP:   addr.IP,
					Mask: net.CIDRMask(maskLen, maskLen),
				},
				Scope: linkmgr.ScopeGlobal,
			})
		}

		// Assign link-local address for configuration updates.
		clientIPv6ll := wirebox.IPv6LLForClient(pubKey)
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

		// Add all assigned peer addresses to the cryptokey router config so
		// Wireguard will let it through.
		allowedIPs := make([]net.IPNet, 0, len(clCfg.Addrs))
		for _, addr := range clCfg.Addrs {
			_, maskLen := addr.Mask.Size()
			allowedIPs = append(allowedIPs, net.IPNet{
				IP:   addr.IP,
				Mask: net.CIDRMask(maskLen, maskLen),
			})
		}
		allowedIPs = append(allowedIPs, net.IPNet{
			IP:   clientIPv6ll,
			Mask: net.CIDRMask(128, 128),
		})

		iface, created, err := wirebox.CreateWG(m, clCfg.ServerIf, wgtypes.Config{
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
			log.Println("created link", clCfg.ServerIf, "for", pubKey)
			links = append(links, iface)
		} else {
			log.Println("using existing link", clCfg.ServerIf, "for", pubKey)
		}
	}

	return allIfs, links, nil
}
