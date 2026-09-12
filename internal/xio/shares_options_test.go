package xio

// sharesOptions reports whether g and other hold the same private Options
// pointer. Tests use this instead of comparing Options() snapshots.
func sharesOptions(g, other *Global) bool {
	return g != nil && other != nil && g.options != nil && g.options == other.options
}
