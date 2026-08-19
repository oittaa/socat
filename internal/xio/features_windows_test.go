//go:build windows

package xio

func expectedFeatureFlags() map[string]bool {
	return featureFlagExpectations(false, false, false)
}
