package wsopen

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// wsHijacker is a ResponseWriter + Hijacker over an already-accepted TCP conn
// so coder/websocket.Accept can complete the HTTP upgrade.
type wsHijacker struct {
	conn   net.Conn
	bufr   *bufio.Reader
	header http.Header
	wrote  bool
}

func newWSHijacker(c net.Conn, br *bufio.Reader) *wsHijacker {
	return &wsHijacker{conn: c, bufr: br, header: make(http.Header)}
}

func (h *wsHijacker) Header() http.Header { return h.header }

func (h *wsHijacker) Write(p []byte) (int, error) {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	return h.conn.Write(p)
}

func (h *wsHijacker) WriteHeader(status int) {
	if h.wrote {
		return
	}
	h.wrote = true
	_, _ = fmt.Fprintf(h.conn, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	_ = h.header.Write(h.conn)
	_, _ = h.conn.Write([]byte("\r\n"))
}

func (h *wsHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	bw := bufio.NewWriter(h.conn)
	return h.conn, bufio.NewReadWriter(h.bufr, bw), nil
}

func (h *wsHijacker) Flush() {
	// no extra buffer
}
