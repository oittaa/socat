package addrconfig

import (
	"strings"
	"testing"
)

func TestSourcePortRejectsServiceNames(t *testing.T) {
	addresses := []struct {
		spec  string
		facts Facts
	}{
		{"TCP:127.0.0.1:9", tcpConnect},
		{"TCP-LISTEN:9", Facts{Type: "TCP-LISTEN", Role: AddressRoleListen}},
		{"UDP-RECV:9", Facts{Type: "UDP-RECV", Kind: AddressKindUDP, Role: AddressRoleReceive}},
	}
	for _, address := range addresses {
		for _, option := range []string{"sourceport", "sp"} {
			spec := address.spec + "," + option + "=x11"
			_, err := Decode(mustParseSpec(t, spec), address.facts)
			if err == nil || !strings.Contains(err.Error(), "invalid port") {
				t.Fatalf("%s: %v", spec, err)
			}
		}
	}
}

func TestSourcePortDecodesNumericForms(t *testing.T) {
	cases := []struct {
		value string
		want  uint16
		text  string
		ok    bool
	}{
		{value: "6000", want: 6000, text: "6000", ok: true},
		{value: "+6000", want: 6000, text: "+6000", ok: true},
		{value: "06000", want: 3072, text: "06000", ok: true},
		{value: "+06000", want: 3072, text: "+06000", ok: true},
		{value: "0x1770", want: 6000, text: "0x1770", ok: true},
		{value: "+0x1770", want: 6000, text: "+0x1770", ok: true},
		{value: "0", want: 0, text: "0", ok: true},
		{value: "-0", want: 0, text: "-0", ok: true},
		{value: "65535", want: 65535, text: "65535", ok: true},
		{value: "0xffff", want: 65535, text: "0xffff", ok: true},
		{value: "0177777", want: 65535, text: "0177777", ok: true},
		{value: `" 6000"`, want: 6000, text: " 6000", ok: true},
		{value: "65536"},
		{value: "0x10000"},
		{value: "0200000"},
		{value: "080"},
		{value: "6000abc"},
		{value: "0b10"},
		{value: "+0b10"},
		{value: "-1"},
		{value: `"6000 "`},
		{value: "++6000"},
		{value: "+"},
		{value: "0x"},
	}
	for _, tc := range cases {
		spec := "TCP:127.0.0.1:9,sourceport=" + tc.value
		got, err := Decode(mustParseSpec(t, spec), tcpConnect)
		if !tc.ok {
			if err == nil || !strings.Contains(err.Error(), "invalid port") {
				t.Fatalf("%s: %v", spec, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		port := got.Network.SourcePort
		if !got.Network.SourcePortSet || !port.Numeric || port.Number != tc.want || port.Text() != tc.text {
			t.Fatalf("%s: %+v text=%q", spec, port, port.Text())
		}
	}
}

func TestServiceNamesStayOnAddressAndProxyPorts(t *testing.T) {
	got := decodeSpec(t, "TCP:127.0.0.1:http,bind=127.0.0.1:x11")
	if got.Network.TargetPort.Numeric || got.Network.TargetPort.Text() != "http" {
		t.Fatalf("address port=%+v", got.Network.TargetPort)
	}
	if !got.Network.BindPortSet || got.Network.BindPort.Numeric || got.Network.BindPort.Text() != "x11" {
		t.Fatalf("bind port=%+v", got.Network.BindPort)
	}

	listen, err := Decode(mustParseSpec(t, "TCP-LISTEN:http"), Facts{Type: "TCP-LISTEN", Role: AddressRoleListen})
	if err != nil {
		t.Fatal(err)
	}
	if listen.Network.ListenPort.Numeric || listen.Network.ListenPort.Text() != "http" {
		t.Fatalf("listen port=%+v", listen.Network.ListenPort)
	}

	proxy, err := Decode(mustParseSpec(t, "PROXY:proxy.test:target.test:www,proxyport=http"),
		Facts{Type: "PROXY", Kind: AddressKindPROXY, Role: AddressRoleConnect})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Proxy.TargetPort.Numeric || proxy.Proxy.TargetPort.Text() != "www" {
		t.Fatalf("target port=%+v", proxy.Proxy.TargetPort)
	}
	if !proxy.Proxy.PortSet || proxy.Proxy.Port.Numeric || proxy.Proxy.Port.Text() != "http" {
		t.Fatalf("proxyport=%+v", proxy.Proxy.Port)
	}
}
