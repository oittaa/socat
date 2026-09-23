//go:build windows

package xio

// Feature flags for -V and -h. Values are fixed for this OS.
const (
	FeatureTUN           = false
	FeatureINTERFACE     = false
	FeatureABSTRACT      = false
	FeatureEXEC          = false
	FeaturePTY           = false
	FeatureSOCKETPAIR    = false
	FeatureSTALL         = false
	FeatureUNIXDatagram  = false
	FeatureUNIXSeqpacket = false
	FeatureGENERICSOCKET = false
	FeatureRAWIP         = false
	FeatureNAMESPACES    = false
	FeaturePOSIXMQ       = false
	FeatureSCTP          = false
	FeatureVSOCK         = false
	FeatureACCEPTFD      = false
)
