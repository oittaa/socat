package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// ForkLimits reads fork and max-children. A present but invalid
// max-children value, or max-children without fork, is an error.
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
