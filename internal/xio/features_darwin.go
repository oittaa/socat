//go:build darwin

package xio

// Feature flags for -V and -h. Values are fixed for this OS.
const (
	FeatureTUN           = false
	FeatureINTERFACE     = false
	FeatureABSTRACT      = false
	FeatureEXEC          = true
	FeaturePTY           = true
	FeatureSOCKETPAIR    = true
	FeatureSTALL         = true
	FeatureUNIXDatagram  = true
	FeatureUNIXSeqpacket = false
	FeatureGENERICSOCKET = true
	FeatureRAWIP         = true
	FeatureNAMESPACES    = false
	FeaturePOSIXMQ       = false
	FeatureSCTP          = false
	FeatureVSOCK         = false
	FeatureACCEPTFD      = true
)
