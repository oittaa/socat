//go:build unix

package xio

func init() {
	FeatureEXEC = true
	FeatureSOCKETPAIR = true
	FeatureSTALL = true
	FeatureGENERICSOCKET = true
	FeatureRAWIP = true
}
