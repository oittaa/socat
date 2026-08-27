package classiccatalog

var expectedMissingPTY = map[string]Gap{
	"sitout-eio": {Reason: "PTY sitout-eio (EIO wait after slave close)", Platforms: PlatUnix},
}
