package wirebox

import (
	"net"

	"github.com/foxcpp/wirebox/linkmgr"
)

var SolictIPv6 net.IP = net.ParseIP("fe80:5747:4443:5000::1")

const (
	SolictPort = 22434

	RouteProto = linkmgr.RouteProto
)
