package dtls13

import (
	"testing"
)

func TestUnfragmentedProbesOffByDefault(t *testing.T) {
	client, server, _ := connectionPair(t)
	if client.transport.unfragmented || client.session.canProbe {
		t.Fatal("default client enabled DF probes")
	}
	if server.transport.unfragmented || server.session.canProbe {
		t.Fatal("default listener association enabled DF probes")
	}
}
