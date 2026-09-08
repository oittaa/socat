package cli

import (
	"strings"
)

func helpLineNames(help string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			out[fields[0]] = true
		}
	}
	return out
}
