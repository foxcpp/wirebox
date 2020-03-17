package wboxproto

import (
	"errors"
	"fmt"

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
