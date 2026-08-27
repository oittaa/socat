package classiccatalog

// Windows open flags documented in official doc/socat.yo. They stay required
// on Windows even though the Linux reference -hhh dump does not advertise them.
var expectedMissingOpen = map[string]Gap{
	"binary":    {Reason: "O_BINARY (Windows); required on windows, not the Linux reference dump", Platforms: PlatWindows},
	"text":      {Reason: "O_TEXT (Windows); required on windows, not the Linux reference dump", Platforms: PlatWindows},
	"noinherit": {Reason: "O_NOINHERIT (Windows); required on windows, not the Linux reference dump", Platforms: PlatWindows},
}
