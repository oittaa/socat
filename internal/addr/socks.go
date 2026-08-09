package addr

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// SOCKS4 / SOCKS4A:sockshost:targethost:targetport[,socksport=N][,socksuser=U]
// Classic SOCKS4 CONNECT. SOCKS4A appends hostname when IP is 0.0.0.x (x!=0).
func openSOCKS4Connect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openSOCKS4(ctx, s, mode, g, false)
}

func openSOCKS4AConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openSOCKS4(ctx, s, mode, g, true)
}

func openSOCKS4(ctx context.Context, s parse.Spec, mode Mode, g *Global, socks4a bool) (*Opened, error) {
	socksHost, targetHost, targetPort, err := socksParams(s)
	if err != nil {
		return nil, err
	}
	socksPort := s.OptionValue("socksport", "1080")
	if socksPort == "" {
		socksPort = "1080"
	}
	user := s.OptionValue("socksuser", "")
	if user == "" {
		user = "nobody"
	}

	portNum, err := strconv.Atoi(targetPort)
	if err != nil {
		// service name
		portNum, err = net.LookupPort("tcp", targetPort)
		if err != nil {
			return nil, fmt.Errorf("socks target port: %w", err)
		}
	}
	if portNum < 0 || portNum > 65535 {
		return nil, fmt.Errorf("socks target port out of range")
	}

	// Resolve target to IPv4 for SOCKS4; SOCKS4A may use dummy IP + hostname.
	var ip4 [4]byte
	var use4a bool
	if ip := net.ParseIP(stripBrackets(targetHost)); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("SOCKS4 requires IPv4 target (got %s)", targetHost)
		}
		copy(ip4[:], v4)
	} else {
		ips, e := net.LookupIP(stripBrackets(targetHost))
		if e == nil {
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					copy(ip4[:], v4)
					break
				}
			}
		}
		if ip4 == [4]byte{} {
			if !socks4a {
				return nil, fmt.Errorf("SOCKS4: cannot resolve %s to IPv4", targetHost)
			}
			// SOCKS4A: IP 0.0.0.1 + append hostname
			ip4 = [4]byte{0, 0, 0, 1}
			use4a = true
		}
	}

	addr := net.JoinHostPort(stripBrackets(socksHost), socksPort)
	d := net.Dialer{Timeout: connectTimeout(s)}
	var conn net.Conn
	err = withRetry(ctx, s, g, "SOCKS4", func() error {
		c, e := d.DialContext(ctx, "tcp", addr)
		if e != nil {
			return e
		}
		// Request: VN CD DSTPORT DSTIP USERID\0 [HOSTNAME\0 for 4A]
		req := make([]byte, 0, 8+len(user)+2+len(targetHost)+1)
		req = append(req, 4, 1) // VN=4, CD=CONNECT
		req = binary.BigEndian.AppendUint16(req, uint16(portNum))
		req = append(req, ip4[:]...)
		req = append(req, []byte(user)...)
		req = append(req, 0)
		if use4a || (socks4a && ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] != 0) {
			req = append(req, []byte(stripBrackets(targetHost))...)
			req = append(req, 0)
		}
		if _, e := c.Write(req); e != nil {
			c.Close()
			return e
		}
		// Reply: 8 bytes
		var resp [8]byte
		if _, e := io.ReadFull(c, resp[:]); e != nil {
			c.Close()
			return fmt.Errorf("socks4 reply: %w", e)
		}
		// VN=0, CD=90 success
		if resp[1] != 90 {
			c.Close()
			return fmt.Errorf("socks4 rejected (cd=%d)", resp[1])
		}
		conn = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	rememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = mode
	return &Opened{Stream: st, Label: fmt.Sprintf("SOCKS4:%s:%s", targetHost, targetPort)}, nil
}

func socksParams(s parse.Spec) (socks, host, port string, err error) {
	p := s.Params
	if len(p) >= 3 {
		return p[0], p[1], p[2], nil
	}
	if len(p) == 2 {
		h, pt, e := net.SplitHostPort(p[1])
		if e == nil {
			return p[0], h, pt, nil
		}
	}
	return "", "", "", fmt.Errorf("%s requires socks-server, host, and port", s.Type)
}
