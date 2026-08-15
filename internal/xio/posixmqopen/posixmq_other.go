//go:build !linux

package posixmqopen

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openPOSIXMQ(_ context.Context, s parse.Spec, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if _, err := queueName(s); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("POSIXMQ is only supported on Linux")
}
