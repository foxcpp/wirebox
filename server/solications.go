package wboxserver

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/foxcpp/wirebox"
	wboxproto "github.com/foxcpp/wirebox/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func serve(stop <-chan struct{}, c *net.UDPConn, clCfgs map[wgtypes.Key]ClientCfg) {
	const maxMsg = 1420
	buffer := make([]byte, maxMsg)

	for {
		readBytes, sender, err := c.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}

			debugLog.Println(err)
			continue
		}
		msg, err := wboxproto.Unpack(buffer[:readBytes])
		if err != nil {
			debugLog.Println(err)
			continue
		}

		var reply wboxproto.Message
		switch msg := msg.(type) {
		case *wboxproto.CfgSolict:
			reply, err = sendConfig(msg, sender, clCfgs)
		default:
			debugLog.Printf("unexpected message type %T from %v", msg, sender)
			continue
		}
		if err != nil {
			debugLog.Println(err)
		}
		if reply == nil {
			continue
		}

		replyDgram, err := wboxproto.Pack(reply)
		if err != nil {
			log.Println("failed to serialize reply", err)
			continue
		}
		debugLog.Println("sending", reply.String(), "to", sender.IP)

		if _, err := c.WriteToUDP(replyDgram, sender); err != nil {
			log.Println(err)
		}
	}
}

func sendConfig(msg *wboxproto.CfgSolict, sender *net.UDPAddr, clCfgs map[wgtypes.Key]ClientCfg) (wboxproto.Message, error) {
	clKey := wirebox.PeerKey{
		Encoded: base64.StdEncoding.EncodeToString(msg.GetPeerPubkey()),
	}
	var err error
	clKey.Bytes, err = wgtypes.NewKey(msg.GetPeerPubkey())
	if err != nil {
		return nil, err
	}

	expectedSender := wirebox.IPv6LLForClient(clKey)
	if !sender.IP.Equal(expectedSender) {
		return &wboxproto.Nack{
			Description: []byte("mismatched IPv6LL and public key in solictation"),
		}, fmt.Errorf("send config: public key (%v) - link-local IPv6 (%v) mismatch", clKey, sender.IP)
	}
	log.Println("configuration for", clKey, "solicted by", sender.IP)

	cfg, ok := clCfgs[clKey.Bytes]
	if !ok {
		return &wboxproto.Nack{
			Description: []byte("no config"),
		}, fmt.Errorf("send config: unknown key %v requested by %v", clKey, sender.IP)
	}

	protoCfg := &wboxproto.Cfg{
		TunPort: uint32(cfg.TunPort),
	}
	if cfg.TunEndpoint4.Net != nil {
		protoCfg.Tun4Endpoint = binary.BigEndian.Uint32(cfg.TunEndpoint4.Addr)
	}
	if cfg.TunEndpoint6.Net != nil {
		protoCfg.Tun6Endpoint = wboxproto.NewIPv6(cfg.TunEndpoint6.Addr)
	}
	for _, addr := range cfg.Addrs {
		prefixLen, ipLen := addr.Net.Mask.Size()
		if ipLen == 32 /* IPv4 */ {
			protoCfg.Net4 = append(protoCfg.Net4, &wboxproto.Net4{
				Addr:      binary.BigEndian.Uint32(addr.Addr.To4()),
				PrefixLen: int32(prefixLen),
			})
		} else {
			protoCfg.Net6 = append(protoCfg.Net6, &wboxproto.Net6{
				Addr:      wboxproto.NewIPv6(addr.Addr),
				PrefixLen: int32(prefixLen),
			})
		}
	}
	for _, route := range cfg.Routes {
		prefixLen, ipLen := route.Dest.Net.Mask.Size()
		// Use IP from Net object as it is "normalized", all bits
		// not in prefix are set to 0.
		if ipLen == 32 /* IPv4 */ {
			protoRoute := &wboxproto.Route4{
				Dest: &wboxproto.Net4{
					Addr:      binary.BigEndian.Uint32(route.Dest.Net.IP.To4()),
					PrefixLen: int32(prefixLen),
				},
			}
			if route.Src != nil {
				protoRoute.Src = binary.BigEndian.Uint32(route.Src.Addr.To4())
			}
			protoCfg.Routes4 = append(protoCfg.Routes4, protoRoute)
		} else {
			protoRoute := &wboxproto.Route6{
				Dest: &wboxproto.Net6{
					Addr:      wboxproto.NewIPv6(route.Dest.Net.IP),
					PrefixLen: int32(prefixLen),
				},
			}
			if route.Src != nil {
				protoRoute.Src = wboxproto.NewIPv6(route.Src.Addr)
			}
			protoCfg.Routes6 = append(protoCfg.Routes6, protoRoute)
		}
	}

	return protoCfg, nil
}
