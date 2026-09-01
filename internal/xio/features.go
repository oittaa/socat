package xio

// Feature flags for -V / -h honesty. Default off; platform init() or an
// opener package turns on what that OS actually implements.
var (
	FeatureTUN           bool
	FeatureINTERFACE     bool
	FeatureABSTRACT      bool
	FeatureEXEC          bool
	FeaturePTY           bool
	FeatureSOCKETPAIR    bool
	FeatureSTALL         bool
	FeatureUNIXDatagram  bool
	FeatureUNIXSeqpacket bool
	FeatureGENERICSOCKET bool
	FeatureRAWIP         bool
	FeatureNAMESPACES    bool
	FeaturePOSIXMQ       bool
	FeatureSCTP          bool
	FeatureVSOCK         bool
	FeatureACCEPTFD      bool
)
