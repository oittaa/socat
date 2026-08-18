//go:build linux

package xio

func init() {
	FeatureABSTRACT = true
	FeatureTUN = true
	FeatureINTERFACE = true
}
