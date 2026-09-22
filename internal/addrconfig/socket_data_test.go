package addrconfig

import (
	"bytes"
	"testing"
)

func TestSocketAddressDecodedFromParamsNotRaw(t *testing.T) {
	spec := mustParseSpec(t, "SOCKET-SENDTO:2:2:17:x00007f000001")
	spec.Raw = "SOCKET-SENDTO:9:9:9:xffffffff"
	got, err := Decode(spec, Facts{Type: "SOCKET-SENDTO", Kind: AddressKindSocket, Role: AddressRoleSendTo})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x00, 0x7f, 0x00, 0x00, 0x01}
	if !bytes.Equal(got.Network.RawSocket.Address, want) {
		t.Fatalf("address=%x want %x", got.Network.RawSocket.Address, want)
	}
}

func TestSocketQuotedDataKeepsStringBytes(t *testing.T) {
	spec := mustParseSpec(t, `SOCKET-SENDTO:2:2:17:"a:b"`)
	spec.Raw = "SOCKET-SENDTO:2:2:17:x0000"
	got, err := Decode(spec, Facts{Type: "SOCKET-SENDTO", Kind: AddressKindSocket, Role: AddressRoleSendTo})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{'a', ':', 'b'}
	if !bytes.Equal(got.Network.RawSocket.Address, want) {
		t.Fatalf("address=%q want %q", got.Network.RawSocket.Address, want)
	}
}
