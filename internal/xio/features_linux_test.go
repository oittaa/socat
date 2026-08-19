//go:build linux

package xio

func expectedFeatureFlags() map[string]bool {
	return featureFlagExpectations(true, true, true)
}
