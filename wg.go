package wirebox

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	Cl   *wgctrl.Client
	Conn *rtnetlink.Conn
)

func CreateWG(name string, cfg wgtypes.Config, addrs []rtnetlink.AddressMessage) (iface *net.Interface, created bool, err error) {
	iface, err = net.InterfaceByName(name)
	if err != nil {
		created = true
		// Assuming we don't have the interface, create it.
		err := Conn.Link.New(&rtnetlink.LinkMessage{
			Type:  65534, // Seems to be set by 'ip link add'
			Flags: unix.IFF_NOARP,
			Attributes: &rtnetlink.LinkAttributes{
				Name: name,
				Info: &rtnetlink.LinkInfo{
					Kind: "wireguard",
				},
			},
		})
		if err != nil {
			return nil, false, fmt.Errorf("wg create: new link: %w", err)
		}
	}

	if err := Cl.ConfigureDevice(name, cfg); err != nil {
		return nil, false, fmt.Errorf("wg create: configure: %w", err)
	}

	iface, err = net.InterfaceByName(name)
	if err != nil {
		return nil, false, fmt.Errorf("wg create: %w", err)
	}

	err = Conn.Link.Set(&rtnetlink.LinkMessage{
		Family: 0,
		Type:   0,
		Index:  uint32(iface.Index),
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	})
	if err != nil {
		return nil, false, fmt.Errorf("wg create: set up: %w", err)
	}

	for i, addr := range addrs {
		addr.Index = uint32(iface.Index)
		err = Conn.Address.New(&addr)
		if err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			if created {
				if delerr := Conn.Link.Delete(uint32(iface.Index)); delerr != nil {
					log.Println("error:", delerr)
				}
			}
			return nil, false, fmt.Errorf("wg create: set addr %v: %w", i, err)
		}
	}

	return iface, created, nil
}

type PeerKey struct {
	Encoded string
	Bytes   wgtypes.Key
}

func NewPeerKey(encoded string) (PeerKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return PeerKey{}, fmt.Errorf("decode peer key: %w", err)
	}
	key, err := wgtypes.NewKey(keyBytes)
	return PeerKey{
		Encoded: encoded,
		Bytes:   key,
	}, err
}

func (k PeerKey) String() string {
	return k.Encoded
}

// AsPrivateKey converts the ed25519 private key stored in PeerKey to
// ed25519.PrivateKey.
func (k PeerKey) AsPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(k.Bytes[:])
}

// AsPrivateKey converts the ed25519 *public* key stored in PeerKey to
// ed25519.PublicKey.
func (k PeerKey) AsPublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(k.Bytes[:])
}

func (k PeerKey) PublicFromPrivate() PeerKey {
	pubKey := k.Bytes.PublicKey()
	return PeerKey{
		Encoded: base64.StdEncoding.EncodeToString(pubKey[:]),
		Bytes:   pubKey,
	}
}

func (k *PeerKey) UnmarshalText(text []byte) error {
	k.Encoded = string(text)

	var err error
	*k, err = NewPeerKey(k.Encoded)
	return err
}

// Initialize global RTNETLINK connections.
func init() {
	var err error
	Cl, err = wgctrl.New()
	if err != nil {
		log.Println("wgctrl new:", err)
		os.Exit(1)
	}
	Conn, err = rtnetlink.Dial(nil)
	if err != nil {
		log.Println("rtnetlink new:", err)
		os.Exit(1)
	}
}
