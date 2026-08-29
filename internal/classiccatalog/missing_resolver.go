package classiccatalog

// Resolver / getaddrinfo options that remain implementation backlog.
// Per-address AI_PASSIVE / AI_V4MAPPED / AI_ALL and res-usevc are implemented.
// Remaining libc _res flags are unsupportedResolver (not backlog): this port
// never mutates process-global resolver state.
var expectedMissingResolver = map[string]Gap{
	// Empty: implemented or classified unsupported / foreign.
}
