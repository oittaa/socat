package classiccatalog

// FD options other than the ioctl family (see missing_ioctl.go).
// shut-down is PR D (ordered howtoshut with shut-none/close/null).
var expectedMissingFD = map[string]Gap{
	"cloexec":   {Reason: "FD_CLOEXEC at PH_LATE", Platforms: PlatUnix},
	"shut-down": {Reason: "classic howtoshut=down; last enabled shut-* occurrence wins (PR D)", Platforms: PlatAll},
}
