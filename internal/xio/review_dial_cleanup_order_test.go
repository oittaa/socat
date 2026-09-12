package xio

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestOpenDialedCleanupOrder(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	addr := mustDecodeAddress(t, s)

	type result struct {
		o   *Opened
		err error
	}
	cases := []struct {
		name    string
		wantErr bool
		open    func(*testing.T, []func()) result
	}{
		{
			name:    "dial failure",
			wantErr: true,
			open: func(t *testing.T, cleanup []func()) result {
				o, err := OpenDialed(context.Background(), addr, nil, Dialed{
					Dial:    func(context.Context) (net.Conn, error) { return nil, errors.New("dial failed") },
					Cleanup: cleanup,
				})
				return result{o, err}
			},
		},
		{
			name:    "wrap failure",
			wantErr: true,
			open: func(t *testing.T, cleanup []func()) result {
				c1, c2 := net.Pipe()
				t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
				o, err := OpenDialed(context.Background(), addr, nil, Dialed{
					Dial: func(context.Context) (net.Conn, error) { return c1, nil },
					Wrap: func(net.Conn) (relay.Stream, error) {
						return nil, errors.New("wrap failed")
					},
					Cleanup: cleanup,
				})
				return result{o, err}
			},
		},
		{
			name: "close",
			open: func(t *testing.T, cleanup []func()) result {
				c1, c2 := net.Pipe()
				t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
				o, err := OpenDialed(context.Background(), addr, nil, Dialed{
					Dial: func(context.Context) (net.Conn, error) { return c1, nil },
					Wrap: func(c net.Conn) (relay.Stream, error) {
						return relay.NetStream{Conn: c}, nil
					},
					Cleanup: cleanup,
				})
				if err != nil {
					return result{o, err}
				}
				return result{o, o.Close()}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			n := 0
			cleanup := []func(){
				func() { n++; order = append(order, "A") },
				func() { n++; order = append(order, "B") },
			}
			res := tc.open(t, cleanup)
			if tc.wantErr {
				if res.err == nil {
					t.Fatal("expected error")
				}
			} else if res.err != nil {
				t.Fatal(res.err)
			}
			if got := strings.Join(order, ","); got != "B,A" {
				t.Fatalf("order=%q want B,A", got)
			}
			if n != 2 {
				t.Fatalf("cleanups=%d want 2", n)
			}
			if res.o != nil {
				if err := res.o.Close(); err != nil {
					t.Fatal(err)
				}
				if n != 2 {
					t.Fatalf("second Close reran cleanup: n=%d", n)
				}
			}
		})
	}
}
