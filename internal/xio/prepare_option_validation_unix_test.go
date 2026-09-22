//go:build linux || darwin

package xio_test

import (
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestPrepareUnixAndExecProtocolFamily(t *testing.T) {
	for _, raw := range []string{
		"UNIX-LISTEN:/tmp/socat-pf-unix,pf=1",
		"UNIX-CONNECT:/tmp/socat-pf-unix,pf=1",
		"EXEC:/bin/true,pf=1",
		"SOCKETPAIR,pf=1",
	} {
		if _, err := xio.PrepareSpec(mustParseSpec(t, raw)); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	_, err := xio.PrepareSpec(mustParseSpec(t, "UNIX-LISTEN:/tmp/socat-pf-unix,pf=2"))
	if err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("UNIX pf=2 error=%v", err)
	}
}

func TestPrepareResolvesOwnerNames(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(account.Username, ":,") {
		t.Skip("account name contains an address separator")
	}
	prepared, err := xio.PrepareSpec(mustParseSpec(t, "CREATE:/tmp/socat-owner-name,user="+account.Username))
	if err != nil {
		t.Fatal(err)
	}
	owner := preparedOwner(t, prepared, addrconfig.FileActionUser)
	if !owner.Numeric || strconv.Itoa(owner.ID) != account.Uid {
		t.Fatalf("user %s resolved to %+v", account.Username, owner)
	}

	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(group.Name, ":,") {
		t.Skip("group name contains an address separator")
	}
	prepared, err = xio.PrepareSpec(mustParseSpec(t, "CREATE:/tmp/socat-owner-group,group="+group.Name))
	if err != nil {
		t.Fatal(err)
	}
	owner = preparedOwner(t, prepared, addrconfig.FileActionGroup)
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Numeric || owner.ID != gid {
		t.Fatalf("group %s resolved to %+v", group.Name, owner)
	}
}

func TestPrepareUserGroupStrtoul(t *testing.T) {
	prepared, err := xio.PrepareSpec(mustParseSpec(t, "CREATE:/tmp/socat-owner-hex,user=0x10,group=0x20"))
	if err != nil {
		t.Fatal(err)
	}
	userRef := preparedOwner(t, prepared, addrconfig.FileActionUser)
	groupRef := preparedOwner(t, prepared, addrconfig.FileActionGroup)
	if !userRef.Numeric || userRef.ID != 16 || !groupRef.Numeric || groupRef.ID != 32 {
		t.Fatalf("user=%+v group=%+v", userRef, groupRef)
	}

	for _, raw := range []string{
		"CREATE:/tmp/socat-owner-bad,user=08",
		"CREATE:/tmp/socat-owner-bad,group=08",
		"CREATE:/tmp/socat-owner-bad,user=-1",
	} {
		_, err := xio.PrepareSpec(mustParseSpec(t, raw))
		if err == nil {
			t.Fatalf("%s was accepted", raw)
		}
	}
	_, err = xio.PrepareSpec(mustParseSpec(t, "CREATE:/tmp/socat-owner-bad,group=nosuchgroup"))
	if err == nil || !strings.Contains(err.Error(), "no such group") {
		t.Fatalf("group error=%v", err)
	}
}
