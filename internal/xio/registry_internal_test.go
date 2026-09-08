package xio

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
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
