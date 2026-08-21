package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// ForkLimits reads the classic fork and max-children options. A present but
// invalid max-children value, or max-children without fork, is a classic-style
// error (xioopts rejects both instead of ignoring them).
func ForkLimits(s parse.Spec) (fork bool, maxChildren int, err error) {
	fork = s.BoolOption("fork")
	if v := s.OptionValue("max-children", ""); v != "" {
		n, e := ParsePositiveInt(v)
		if e != nil {
			return false, 0, fmt.Errorf("%s: invalid max-children %q", s.Type, v)
		}
		if !fork {
			return false, 0, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
		}
		maxChildren = n
	}
	return fork, maxChildren, nil
}
