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

	prepared, err = xio.PrepareSpec(mustParseSpec(t, "CREATE:/tmp/socat-owner-group,group=root"))
	if err != nil {
		t.Fatal(err)
	}
	owner = preparedOwner(t, prepared, addrconfig.FileActionGroup)
	if !owner.Numeric || owner.ID != 0 {
		t.Fatalf("group root resolved to %+v", owner)
	}
}
