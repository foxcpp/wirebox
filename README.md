Wirebox **WIP**
=========
> Dynamic WireGuard tunnel configuration daemon.

_Both client & server are Linux-only now._

## Features

- Clients need no configuration other than ed25519 key pair and server endpoint
  (IP + port).
- Multicast-friendly thanks to PtP mode.
- Can assign IPs dynamically if you do not care.
- Centralized configuration at a single node (server).

## Server

Acts as a router between connected clients (and possibly other networks),
sends client configurations on request using [WGDCP](#WGDCP) protocol.

### Installation & configuration

Install [Go](https://golang.org) toolchain and run the following to install its
executable:
```
$ env GO111MODULE=on go get github.com/foxcpp/wirebox/cmd/wboxd@latest
```
Grab example configuration file [here](cmd/wboxd/wboxd.example.toml).
`wboxd` looks for the configuration file named wboxd.toml in the current
directory. This can be changed using `-config` command line option.

Do not forget to enable IP forwarding and adjust your firewall configuration
appropriately:
```
# sysctl net.ipv4.ip_forward=1
```

## Client

CLI utility that requests configuration from the server using [WGDCP](#WGDCP)
protocol, configures the WireGuard tunnel appropriately and exits.

### Installation & configuration

Mostly the same as Server, just replace `wboxd` in the `go get` command.
And the example configuration is here: [cmd/wbox/wbox.example.toml].

## WGDCP
> WireGuard Dynamic Configuration Protocol

Simple ProtoBuf-based protocol running on top of UDP/IPv6 inside
"configuration" WireGuard tunnel. Intended as a specialized minimal DHCP
replacement.

The configuration received from the server is authenticated because it is
received over WireGuard tunnel.

The server uses strict "Allowed IPs" options for all tunnels and therefore will
not allow IP spoofing to happen. Filtering is applied to prevent clients from
peeking at configuration of other clients, but it is not bullet-proof.

*TODO: Protocol documentation/specification is non-existent.*
