// Package quicopen implements raw QUIC byte relay (RFC 9000) connect and listen.
// One bidirectional stream via github.com/quic-go/quic-go — not HTTP/3.
package quicopen

import (
	"crypto/tls"
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

const defaultALPN = "socat"

func quicTarget(s addrconfig.Address, listen bool) (host, port string, err error) {
	if listen {
		p, err := xio.ListenPort(s)
		if err != nil {
			return "", "", err
		}
		return "", p.Text(), nil
	}
	if !s.Network.TargetSet {
		return "", "", fmt.Errorf("%s requires host and port", s.Type)
	}
	if s.Network.Target.Empty() || s.Network.TargetPort.Empty() {
		return "", "", fmt.Errorf("%s: invalid host/port", s.Type)
	}
	host, port = s.Network.Target.Original(), s.Network.TargetPort.Text()
	return host, port, nil
}

func alpnProto(settings addrconfig.TLS) string {
	if settings.ALPN.Set && settings.ALPN.Value != "" {
		return settings.ALPN.Value
	}
	return defaultALPN
}

func withALPN(cfg *tls.Config, alpn string) (*tls.Config, error) {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("openssl-max-proto-version: QUIC requires TLS 1.3 or later")
	}
	cfg.NextProtos = []string{alpn}
	// RFC 9001 requires clients not to offer versions older than TLS 1.3.
	// Preserve a higher minimum if a future TLS implementation supports one.
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return cfg, nil
}
