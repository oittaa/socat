package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

// ForkRequested reports whether fork is enabled on the prepared address.
func ForkRequested(config addrconfig.Address) bool {
	return config.Common.Fork.Enabled.Value
}

// ForkLimits reads prepared fork and max-children. A present max-children
// without fork is an error.
func ForkLimits(config addrconfig.Address) (fork bool, maxChildren int, err error) {
	fork = ForkRequested(config)
	if !config.Common.MaxChildren.Set {
		return fork, 0, nil
	}
	if !fork {
		return false, 0, fmt.Errorf("%s: option max-children not allowed without option fork", config.Type)
	}
	if config.Common.MaxChildren.Value < 1 {
		return fork, 0, fmt.Errorf("%s: invalid max-children %q", config.Type, "0")
	}
	return fork, config.Common.MaxChildren.Value, nil
}
