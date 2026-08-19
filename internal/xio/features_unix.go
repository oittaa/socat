//go:build unix

package xio

func init() {
	FeatureEXEC = true
	FeatureSOCKETPAIR = true
	FeatureSTALL = true
	FeatureUNIXDatagram = true
	FeatureGENERICSOCKET = true
	FeatureRAWIP = true
}
