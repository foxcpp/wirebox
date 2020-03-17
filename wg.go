package wirebox

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"syscall"

	"github.com/foxcpp/wirebox/linkmgr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func CreateWG(m linkmgr.Manager, name string, cfg wgtypes.Config, addrs []linkmgr.Address) (link linkmgr.Link, created bool, err error) {
	link, err = m.GetLink(name)
	if err != nil {
		created = true
		link, err = m.CreateLink(name)
		if err != nil {
			return nil, false, fmt.Errorf("wg create: %w", err)
		}
	}

	if err := link.ConfigureWG(cfg); err != nil {
		return nil, false, fmt.Errorf("wg create: configure: %w", err)
	}

	if err := link.SetUp(true); err != nil {
		return nil, false, fmt.Errorf("wg create: set up: %w", err)
	}

	for i, addr := range addrs {
		if err := link.AddAddr(addr); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			if created {
				if delerr := m.DelLink(link.Index()); delerr != nil {
					log.Println("error:", delerr)
				}
			}
			return nil, false, fmt.Errorf("wg create: set addr %v: %w", i, err)
		}
	}

	return link, created, nil
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
