package xio

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestAddressRegistryRejectsDuplicateNames(t *testing.T) {
	r := newAddressRegistry()
	r.register(AddressDesc{Name: "TCP", Group: GroupTCP, Syntax: "TCP:<host>:<port>"})

	defer func() {
		got := recover()
		if got == nil || !strings.Contains(fmt.Sprint(got), "duplicate address registration: TCP") {
			t.Fatalf("panic=%v", got)
		}
	}()
	r.register(AddressDesc{Name: "tcp", Group: GroupTCP, Syntax: "tcp:<host>:<port>"})
}

func TestAddressRegistrySnapshotsAreDeterministic(t *testing.T) {
	r := newAddressRegistry()
	opener := func(context.Context, parse.Spec, Mode, *Global) (*Opened, error) {
		return nil, nil
	}
	r.register(AddressDesc{Name: "UDP-Z", Group: GroupUDP, Syntax: "UDP-Z:<port>"})
	r.register(AddressDesc{Name: "TCP-A", Group: GroupTCP, Syntax: "TCP-A:<port>"})
	r.register(AddressDesc{Name: "HIDDEN-Z", Opener: opener})
	r.register(AddressDesc{Name: "HIDDEN-A", Opener: opener})

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

func TestAddressRegistryMergesDerivedOptionCaps(t *testing.T) {
	r := newAddressRegistry()
	r.register(AddressDesc{Name: "TCP-LISTEN-X", Group: GroupTCP, Syntax: "TCP-LISTEN-X:<port>", OptionCaps: []string{"extra"}})
	reg, ok := r.registration("tcp-listen-x")
	if !ok {
		t.Fatal("missing registration")
	}
	want := []string{OptCapListen, OptCapIPFilter, OptCapPort, OptCapLowport, "extra"}
	if !reflect.DeepEqual(reg.OptionCaps, want) {
		t.Fatalf("OptionCaps=%v want %v", reg.OptionCaps, want)
	}
}
