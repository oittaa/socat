// Package quicopen implements QUIC (RFC 9000) connect and listen.
// Classic socat has no QUIC. This is a raw byte relay on one bidirectional
// stream via golang.org/x/net/quic — not HTTP/3.
package quicopen

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const defaultALPN = "socat"

func quicTarget(s parse.Spec, listen bool) (host, port string, err error) {
	if listen {
		if len(s.Params) < 1 || s.Params[0] == "" {
			return "", "", fmt.Errorf("%s requires port", s.Type)
		}
		return "", s.Params[0], nil
	}
	return xio.HostPortParams(s)
}

func alpnProto(s parse.Spec) string {
	v := s.OptionValue("alpn", "")
	if v == "" {
		return defaultALPN
	}
	return v
}

func withALPN(cfg *tls.Config, s parse.Spec) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	cfg.NextProtos = []string{alpnProto(s)}
	// QUIC (RFC 9001) is TLS 1.3 only.
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}

func udpNetwork(tcpNet string) string {
	switch strings.ToLower(tcpNet) {
	case "tcp4":
		return "udp4"
	case "tcp6":
		return "udp6"
	default:
		return "udp"
	}
}
