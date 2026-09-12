package dtls13

import (
	"testing"
)

func TestUnfragmentedProbesOffByDefault(t *testing.T) {
	client, server, _ := connectionPair(t)
	if client.config.transport.unfragmented || client.driver.session.working.canProbe {
		t.Fatal("default client enabled DF probes")
	}
	if server.config.transport.unfragmented || server.driver.session.working.canProbe {
		t.Fatal("default listener association enabled DF probes")
	}
}
