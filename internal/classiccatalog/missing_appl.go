package classiccatalog

// Application / transfer options (classic GROUP_APPL).
// lockfile/waitlock are implemented (PR H): advertised and applied at PH_INIT.
var expectedMissingAppl = map[string]Gap{
	// Empty: GROUP_APPL lockfile= and waitlock= are honored on PlatAll.
}
