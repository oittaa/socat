package classiccatalog

// PROXY HTTP/1 CONNECT ignorecr (PR J).
var expectedMissingHTTP = map[string]Gap{
	"ignorecr": {Reason: "HTTP/1 CONNECT response parser accepts LF/CRLF when ignorecr is set (PR J)", Platforms: PlatAll},
}
