package classiccatalog

// FD options other than the ioctl family (see missing_ioctl.go).
var expectedMissingFD = map[string]Gap{
	"cloexec": {Reason: "FD_CLOEXEC at PH_LATE", Platforms: PlatUnix},
}
