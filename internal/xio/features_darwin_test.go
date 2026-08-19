//go:build darwin

package xio

func expectedFeatureFlags() map[string]bool {
	return featureFlagExpectations(true, false, true)
}
