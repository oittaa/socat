package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// ForkLimits reads fork and max-children. A non-positive or unparsable
// max-children value is ignored (classic connect / most listen paths).
func ForkLimits(s parse.Spec) (fork bool, maxChildren int) {
	fork = s.BoolOption("fork")
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, err := ParsePositiveInt(v); err == nil {
			maxChildren = n
		}
	}
	return fork, maxChildren
}

// RequireForkWithMaxChildren returns the classic error when max-children is
// set without fork.
func RequireForkWithMaxChildren(typ string, fork bool, maxChildren int) error {
	if maxChildren > 0 && !fork {
		return fmt.Errorf("%s: option max-children not allowed without option fork", typ)
	}
	return nil
}
