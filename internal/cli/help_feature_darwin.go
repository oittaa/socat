//go:build darwin

package cli

import "github.com/oittaa/socat/internal/xio"

func hideOptFeature(name string) bool {
	if name == "async" && !xio.FeatureFDAsync {
		return true
	}
	switch name {
	case "flock", "flock-nb", "flock-sh", "flock-sh-nb":
		return !xio.FeatureFlock
	default:
		return false
	}
}
