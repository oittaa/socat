package xio

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestAddressRegistryRequiresOptionCaps(t *testing.T) {
	r := newAddressRegistry()
	defer func() {
		got := recover()
		if got == nil || !strings.Contains(fmt.Sprint(got), "requires OptionCaps") {
			t.Fatalf("panic=%v", got)
		}
	}()
	r.register(AddressDesc{Name: "TCP", Group: GroupTCP, Syntax: "TCP:<host>:<port>"})
}

func TestAddressRegistryRejectsDuplicateNames(t *testing.T) {
	r := newAddressRegistry()
	r.register(AddressDesc{Name: "TCP", Group: GroupTCP, Syntax: "TCP:<host>:<port>", OptionCaps: []string{"fd"}})

	defer func() {
		got := recover()
		if got == nil || !strings.Contains(fmt.Sprint(got), "duplicate address registration: TCP") {
			t.Fatalf("panic=%v", got)
		}
	}()
	r.register(AddressDesc{Name: "tcp", Group: GroupTCP, Syntax: "tcp:<host>:<port>", OptionCaps: []string{"fd"}})
}

func TestAddressRegistrySnapshotsAreDeterministic(t *testing.T) {
	r := newAddressRegistry()
	opener := func(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
		return nil, nil
	}
	r.register(AddressDesc{Name: "UDP-Z", Group: GroupUDP, Syntax: "UDP-Z:<port>", OptionCaps: []string{"fd"}})
	r.register(AddressDesc{Name: "TCP-A", Group: GroupTCP, Syntax: "TCP-A:<port>", OptionCaps: []string{"fd"}})
	r.register(AddressDesc{Name: "HIDDEN-Z", Opener: opener, OptionCaps: []string{"fd"}})
	r.register(AddressDesc{Name: "HIDDEN-A", Opener: opener, OptionCaps: []string{"fd"}})

	regs := r.registrations()
	got := make([]string, 0, len(regs))
	for _, reg := range regs {
		got = append(got, reg.Name)
	}
	want := []string{"TCP-A", "UDP-Z", "HIDDEN-A", "HIDDEN-Z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registrations=%v want %v", got, want)
	}

	reg, ok := r.registration("tcp-a")
	if !ok || reg.Name != "TCP-A" || reg.Group != GroupTCP {
		t.Fatalf("registration=%+v ok=%v", reg, ok)
	}
}

func TestAddressRegistryAliasFallbackAndDirectWins(t *testing.T) {
	canonOpener := func(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
		return nil, fmt.Errorf("canonical")
	}
	directOpener := func(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
		return nil, fmt.Errorf("direct")
	}

	r := newAddressRegistry()
	r.register(AddressDesc{
		Name:       "TCP-LISTEN",
		Group:      GroupTCP,
		Syntax:     "TCP-LISTEN:<port>",
		Opener:     canonOpener,
		OptionCaps: CapsTCPListen,
		Aliases:    []string{"INET-L", "INET-LISTEN"},
	})
	r.register(AddressDesc{
		Name:       "TCP-L",
		Group:      GroupTCP,
		Syntax:     "TCP-L:<port>",
		Opener:     directOpener,
		OptionCaps: CapsTCPListen,
	})

	d, ok := r.resolve("inet-l")
	if !ok || d.Name != "TCP-LISTEN" {
		t.Fatalf("INET-L resolve=%+v ok=%v; want TCP-LISTEN (tag-1.8.1.3 addressnames[] INET-L)", d, ok)
	}
	fn, ok := r.opener("INET-LISTEN")
	if !ok {
		t.Fatal("INET-LISTEN opener missing")
	}
	_, err := fn(context.Background(), parse.Spec{}, ModeRDWR, nil)
	if err == nil || err.Error() != "canonical" {
		t.Fatalf("INET-LISTEN opener err=%v want canonical", err)
	}

	reg, ok := r.registration("INET-L")
	if !ok || reg.Name != "TCP-LISTEN" || reg.Group != GroupTCP {
		t.Fatalf("INET-L registration=%+v ok=%v", reg, ok)
	}

	d, ok = r.resolve("TCP-L")
	if !ok || d.Name != "TCP-L" {
		t.Fatalf("TCP-L direct registration must win, got %+v ok=%v", d, ok)
	}
	fn, ok = r.opener("tcp-l")
	if !ok {
		t.Fatal("TCP-L opener missing")
	}
	_, err = fn(context.Background(), parse.Spec{}, ModeRDWR, nil)
	if err == nil || err.Error() != "direct" {
		t.Fatalf("TCP-L opener err=%v want direct", err)
	}
}

func TestAddressRegistryUnknownAndDisabledAliases(t *testing.T) {
	r := newAddressRegistry()
	if _, ok := r.resolve("INET"); ok {
		t.Fatal("INET must stay unknown when TCP-CONNECT is unregistered")
	}
	if _, ok := r.resolve("DCCP"); ok {
		t.Fatal("DCCP must stay unknown")
	}
	if _, ok := r.resolve("ACCEPT"); ok {
		t.Fatal("ACCEPT must stay unknown while ACCEPT-FD is unregistered")
	}
	if _, ok := r.resolve("-"); ok {
		t.Fatal("parser shorthand - must not resolve in the registry")
	}

	r.register(AddressDesc{
		Name:       "INTERFACE",
		Group:      GroupTUN,
		Syntax:     "INTERFACE:<ifname>",
		Enabled:    func() bool { return false },
		Opener:     func(context.Context, parse.Spec, Mode, *Global) (*Opened, error) { return nil, nil },
		OptionCaps: CapsINTERFACE,
		Aliases:    []string{"IF"},
	})
	reg, ok := r.registration("IF")
	if !ok {
		t.Fatal("IF should resolve to disabled INTERFACE")
	}
	if reg.Enabled {
		t.Fatal("disabled canonical must leave IF disabled")
	}
	if reg.Name != "INTERFACE" {
		t.Fatalf("IF Name=%q want INTERFACE", reg.Name)
	}
}

func TestAddressRegistryKeepsExplicitOptionCaps(t *testing.T) {
	r := newAddressRegistry()
	r.register(AddressDesc{Name: "TCP-LISTEN-X", Group: GroupTCP, Syntax: "TCP-LISTEN-X:<port>", OptionCaps: []string{"extra"}})
	reg, ok := r.registration("tcp-listen-x")
	if !ok {
		t.Fatal("missing registration")
	}
	want := uniqueCaps([]string{"extra"})
	if !reflect.DeepEqual(reg.OptionCaps, want) {
		t.Fatalf("OptionCaps=%v want %v (explicit caps must not be merged with name heuristics)", reg.OptionCaps, want)
	}
}
