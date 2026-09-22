package addrconfig

import "fmt"

// WrongParameterCount reports that an address has the wrong number of
// positional parameters. min and max are inclusive; max < 0 means no maximum.
// usage is the address form shown after "usage:", or empty to omit it.
func WrongParameterCount(name string, got, min, max int, usage string) error {
	msg := fmt.Sprintf("wrong number of parameters (%d instead of %s)", got, parameterExpect(min, max))
	if usage != "" {
		msg += ": usage: " + usage
	}
	return fmt.Errorf("%s: %s", name, msg)
}

func parameterCountError(got, min, max int) error {
	return fmt.Errorf("wrong number of parameters (%d instead of %s)", got, parameterExpect(min, max))
}

func parameterExpect(min, max int) string {
	switch {
	case max < 0:
		return fmt.Sprintf("%d or more", min)
	case min == max:
		return fmt.Sprintf("%d", min)
	default:
		return fmt.Sprintf("%d or %d", min, max)
	}
}
