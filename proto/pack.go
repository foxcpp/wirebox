package wboxproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/golang/protobuf/proto"
)

//go:generate protoc --go_out=. protocol.proto

type Message = proto.Message

type MsgType byte

const (
	MsgSolict MsgType = 1
	MsgCfg    MsgType = 2
	MsgNack   MsgType = 3

	Version byte = 1
)

var (
	ErrUnknownVersion = errors.New("proto: unknown protocol version")
)

func Unpack(b []byte) (proto.Message, error) {
	if len(b) < 2 {
		return nil, errors.New("proto: malformed datagram")
	}

	version := b[0]
	msgType := MsgType(b[1])

	if version != Version {
		return nil, ErrUnknownVersion
	}

	var msg proto.Message
	switch msgType {
	case MsgSolict:
		msg = &CfgSolict{}
	case MsgCfg:
		msg = &Cfg{}
	case MsgNack:
		msg = &Nack{}
	default:
		return nil, errors.New("proto: unknown message type")
	}

	if err := proto.Unmarshal(b[2:], msg); err != nil {
		return nil, fmt.Errorf("proto: unpack: %w", err)
	}
	return msg, nil
}

func Pack(msg proto.Message) ([]byte, error) {
	var msgType MsgType
	switch msg.(type) {
	case *CfgSolict:
		msgType = MsgSolict
	case *Cfg:
		msgType = MsgCfg
	case *Nack:
		msgType = MsgNack
	default:
		return nil, errors.New("proto: unknown message type")
	}

	body, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("proto: pack: %w", err)
	}

	payload := make([]byte, 2, len(body)+2)
	payload[0] = Version
	payload[1] = byte(msgType)
	payload = append(payload, body...)
	return payload, nil
}

func (ipv6 *IPv6) AsIP() net.IP {
	if ipv6 == nil {
		return nil
	}
	res := make(net.IP, 16)
	binary.BigEndian.PutUint64(res[:8], ipv6.High)
	binary.BigEndian.PutUint64(res[8:], ipv6.Low)
	return res
}

func NewIPv6(addr net.IP) *IPv6 {
	if addr == nil {
		return nil
	}
	addr = addr.To16()
	return &IPv6{
		High: binary.BigEndian.Uint64(addr[:8]),
		Low:  binary.BigEndian.Uint64(addr[8:]),
	}
}

func IPv4(a uint32) net.IP {
	return net.IPv4(
		byte(a&0xFF000000>>24),
		byte(a&0x00FF0000>>16),
		byte(a&0x0000FF00>>8),
		byte(a&0x000000FF),
	)
}
