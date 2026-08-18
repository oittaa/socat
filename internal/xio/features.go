package xio

// Feature flags for -V / -h honesty. Default off; platform init() turns on
// what that OS actually implements.
var (
	FeatureTUN           bool
	FeatureINTERFACE     bool
	FeatureABSTRACT      bool
	FeatureEXEC          bool
	FeaturePTY           bool
	FeatureSOCKETPAIR    bool
	FeatureSTALL         bool
	FeatureGENERICSOCKET bool
	FeatureRAWIP         bool
)
