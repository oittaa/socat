package classiccatalog

// Application / transfer options (classic GROUP_APPL).
// cr is PR D; lockfile/waitlock are PR H.
var expectedMissingAppl = map[string]Gap{
	"cr":       {Reason: "classic cr line termination (NL↔CR); shares the line-termination field with crnl/crlf (PR D)", Platforms: PlatAll},
	"lockfile": {Reason: "address-option lockfile=; reuse CLI -L atomic lock (PR H)", Platforms: PlatAll},
	"waitlock": {Reason: "address-option waitlock=; reuse CLI -W atomic lock (PR H)", Platforms: PlatAll},
}
