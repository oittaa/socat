package classiccatalog

// Application / transfer options (classic GROUP_APPL).
// lockfile/waitlock are PR H.
var expectedMissingAppl = map[string]Gap{
	"lockfile": {Reason: "address-option lockfile=; reuse CLI -L atomic lock (PR H)", Platforms: PlatAll},
	"waitlock": {Reason: "address-option waitlock=; reuse CLI -W atomic lock (PR H)", Platforms: PlatAll},
}
