package proxyopen

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

type httpMajor int

const (
	httpVer1 httpMajor = 1
	httpVer2 httpMajor = 2
	httpVer3 httpMajor = 3
)

func parseHTTPVersion(s parse.Spec) (httpMajor, error) {
	v := s.OptionValue("http-version", "1.0")
	if v == "" {
		v = "1.0"
	}
	switch strings.TrimSpace(v) {
	case "1", "1.0", "1.1":
		return httpVer1, nil
	case "2", "2.0":
		return httpVer2, nil
	case "3", "3.0":
		return httpVer3, nil
	default:
		return 0, fmt.Errorf("http-version=%s not supported (use 1.0, 1.1, 2, or 3)", v)
	}
}

func proxyALPN(s parse.Spec, def string) string {
	if v := s.OptionValue("alpn", ""); v != "" {
		return v
	}
	return def
}
