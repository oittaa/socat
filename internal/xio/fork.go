package xio

import (
	"context"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// ForkLimits reads prepared fork and max-children. A present max-children
// without fork is an error.
func ForkLimits(ctx context.Context, s parse.Spec) (fork bool, maxChildren int, err error) {
	config, err := addressFromOpening(ctx, s)
	if err != nil {
		return false, 0, err
	}
	fork = config.Common.Fork.Enabled.Value
	if !config.Common.MaxChildren.Set {
		return fork, 0, nil
	}
	if !fork {
		return false, 0, fmt.Errorf("%s: option max-children not allowed without option fork", config.Type)
	}
	return fork, config.Common.MaxChildren.Value, nil
}
