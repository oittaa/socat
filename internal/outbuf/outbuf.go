// Package outbuf builds text and writes it once so help/report printers
// do not ignore a fmt.Fprint error on every line.
package outbuf

import (
	"fmt"
	"io"
	"strings"
)

// Buf accumulates formatted text. Flush writes it to w in one call.
type Buf struct {
	b   strings.Builder
	err error
}

func (o *Buf) note(err error) {
	if err != nil && o.err == nil {
		o.err = err
	}
}

func (o *Buf) Printf(format string, a ...any) {
	_, err := fmt.Fprintf(&o.b, format, a...)
	o.note(err)
}

func (o *Buf) Print(a ...any) {
	_, err := fmt.Fprint(&o.b, a...)
	o.note(err)
}

func (o *Buf) Println(a ...any) {
	_, err := fmt.Fprintln(&o.b, a...)
	o.note(err)
}

func (o *Buf) Flush(w io.Writer) error {
	if o.err != nil {
		return o.err
	}
	_, err := io.WriteString(w, o.b.String())
	return err
}
