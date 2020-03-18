package wboxserver

import (
	"net"

	"github.com/foxcpp/wirebox"
	"github.com/foxcpp/wirebox/linkmgr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func createMultipointLink(m linkmgr.Manager, scfg SrvConfig, clientKeys []wirebox.PeerKey, clientCfgs map[wgtypes.Key]ClientCfg) (linkmgr.Link, bool, error) {
	cfg := wgtypes.Config{
		PrivateKey:   &scfg.PrivateKey.Bytes,
		ListenPort:   &scfg.PortLow,
		ReplacePeers: true,
	}

	// Here we configure only one interface with one address/subnet at the
	// server and let WireGuard take care of routing by filling Allowed IPs
	// appropriately.
	//
	// IP multicast will *not* work at all in this configuration.

	linkAddrs := []linkmgr.Address{
		{
			IPNet: net.IPNet{
				IP:   wirebox.SolictIPv6,
				Mask: net.CIDRMask(8, 128),
			},
			Scope: linkmgr.ScopeLink,
		},
	}
	if !scfg.Server4.PtP {
		linkAddrs = append(linkAddrs, linkmgr.Address{
			IPNet: net.IPNet{
				IP:   scfg.Server4.Addr,
				Mask: scfg.Server4.Net.Mask,
			},
			Scope: linkmgr.ScopeGlobal,
		})
	}
	if !scfg.Server6.PtP {
		linkAddrs = append(linkAddrs, linkmgr.Address{
			IPNet: net.IPNet{
				IP:   scfg.Server6.Addr,
				Mask: scfg.Server6.Net.Mask,
			},
			Scope: linkmgr.ScopeGlobal,
		})
	}

	for _, pubKey := range clientKeys {
		clCfg := clientCfgs[pubKey.Bytes]

		clientLL := wirebox.IPv6LLForClient(pubKey)
		addrs := []net.IPNet{
			{ // Permit link-local communication over configuration interface.
				IP:   clientLL,
				Mask: net.CIDRMask(128, 128),
			},
		}

		for _, clAddr := range clCfg.Addrs {
			if clAddr.Addr.To4() != nil && scfg.Server4.PtP {
				linkAddrs = append(linkAddrs, linkmgr.Address{
					IPNet: net.IPNet{
						IP:   scfg.Server4.Addr,
						Mask: net.CIDRMask(32, 32),
					},
					Peer: &net.IPNet{
						IP:   clAddr.Addr,
						Mask: net.CIDRMask(32, 32),
					},
					Scope: linkmgr.ScopeGlobal,
				})
			} else if scfg.Server6.PtP {
				linkAddrs = append(linkAddrs, linkmgr.Address{
					IPNet: net.IPNet{
						IP:   scfg.Server6.Addr,
						Mask: net.CIDRMask(128, 128),
					},
					Peer: &net.IPNet{
						IP:   clAddr.Addr,
						Mask: net.CIDRMask(128, 128),
					},
					Scope: linkmgr.ScopeGlobal,
				})
			}

			mask := net.CIDRMask(128, 128)
			if clAddr.Addr.To4() != nil {
				mask = net.CIDRMask(32, 32)
			}
			addrs = append(addrs, net.IPNet{
				IP:   clAddr.Addr,
				Mask: mask,
			})
		}

		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:         pubKey.Bytes,
			ReplaceAllowedIPs: true,
			AllowedIPs:        addrs,
		})
	}

	return wirebox.CreateWG(m, scfg.If, cfg, linkAddrs)
}

func createConfLink(m linkmgr.Manager, scfg SrvConfig, clientKeys []wirebox.PeerKey) (linkmgr.Link, bool, error) {
	cfg := wgtypes.Config{
		PrivateKey:   &scfg.PrivateKey.Bytes,
		ListenPort:   &scfg.PortLow,
		ReplacePeers: true,
	}

	for _, pubKey := range clientKeys {
		clientLL := wirebox.IPv6LLForClient(pubKey)
		debugLog.Printf("IPv6LL for %v: %v", pubKey, clientLL)

		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:         pubKey.Bytes,
			ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{
				// Permit link-local communication over configuration interface.
				{
					IP:   clientLL,
					Mask: net.CIDRMask(128, 128),
				},
			},
		})
	}

	return wirebox.CreateWG(m, scfg.If, cfg, []linkmgr.Address{
		{
			IPNet: net.IPNet{
				IP:   wirebox.SolictIPv6,
				Mask: net.CIDRMask(8, 128),
			},
			Scope: linkmgr.ScopeLink,
		},
	})
}
