package classiccatalog

// BSD/Darwin TCP options documented in official doc/socat.yo. They stay
// required on darwin even though the Linux reference -hhh dump omits them.
var expectedMissingTCPBSD = map[string]Gap{
	"rfc1323":          {Reason: "TCP_RFC1323 (BSD)", Platforms: PlatDarwin},
	"sack-disable":     {Reason: "TCP_SACK_DISABLE (BSD)", Platforms: PlatDarwin},
	"stdurg":           {Reason: "TCP_STDURG (BSD)", Platforms: PlatDarwin},
	"signature-enable": {Reason: "TCP_SIGNATURE_ENABLE (BSD)", Platforms: PlatDarwin},
}
