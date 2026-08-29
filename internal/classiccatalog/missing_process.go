package classiccatalog

// Process-wide setuid/setgid/chroot/substuser spellings live in
// unsupportedProcess (README Unsupported / security-related). Do not call
// them from a session goroutine.
var expectedMissingProcess = map[string]Gap{}
