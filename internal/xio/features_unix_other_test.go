//go:build unix && !linux && !darwin

package xio

func expectedFeatureFlags() map[string]bool {
	return featureFlagExpectations(true, false, false)
}
