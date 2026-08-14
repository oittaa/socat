package proxyopen

import (
	"io"
	"net"
	"time"
)

// pipeConn is a net.Conn over a CONNECT stream: write to the request body,
// read from the response body.
type pipeConn struct {
	r      io.ReadCloser
	w      io.WriteCloser
	local  net.Addr
	remote net.Addr
	extra  []io.Closer
}

func (c *pipeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *pipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *pipeConn) CloseWrite() error { return c.w.Close() }

func (c *pipeConn) Close() error {
	_ = c.w.Close()
	_ = c.r.Close()
	for _, x := range c.extra {
		_ = x.Close()
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.local }
func (c *pipeConn) RemoteAddr() net.Addr { return c.remote }

func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func staticAddr(network, s string) net.Addr { return &strAddr{net: network, s: s} }

type strAddr struct{ net, s string }

func (a *strAddr) Network() string { return a.net }
func (a *strAddr) String() string  { return a.s }
