package classiccatalog

// Remaining IPv4/IPv6 settable sockopts from the PR C set are classified
// elsewhere: ip-mtu / ip-pktoptions live in unsupportedGetOnlyIP (get-only
// kernel options, not a setter backlog). ip-retopts and ip-router-alert
// are implemented on Linux. ip-hdrincl was PR A.
var expectedMissingIP = map[string]Gap{}
