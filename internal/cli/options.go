package cli

import (
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func validateChannelOptions(ch parse.Channel) error {
	_, err := xio.PrepareChannel(ch)
	return err
}

func validateSpecOptions(spec parse.Spec) error {
	_, err := xio.PrepareSpec(spec)
	return err
}
