package xio

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func ParsePositiveInt(v string) (int, error) {
	n, err := ParseIntAny(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid")
	}
	return n, nil
}

func ParseIntAny(v string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 0, 64)
	if err != nil {
		return 0, err
	}
	if n > math.MaxInt || n < math.MinInt {
		return 0, fmt.Errorf("out of range")
	}
	return int(n), nil
}

func TestFirstAvailableLowportFromWrapsDownward(t *testing.T) {
	var tried []int
	port, err := firstAvailableLowportFrom(LowportMin, func(port int) error {
		tried = append(tried, port)
		if port != LowportMax {
			return syscall.EADDRINUSE
		}
		return nil
	})
	if err != nil || port != LowportMax {
		t.Fatalf("port=%d err=%v", port, err)
	}
	if len(tried) != 2 || tried[0] != LowportMin || tried[1] != LowportMax {
		t.Fatalf("tried %v, want [%d %d]", tried, LowportMin, LowportMax)
	}
}

func TestFirstAvailableLowportFromStopsOnOtherErrorAfterWrap(t *testing.T) {
	wantErr := errors.New("permission denied")
	var tried []int
	_, err := firstAvailableLowportFrom(LowportMin, func(port int) error {
		tried = append(tried, port)
		if port == LowportMin {
			return syscall.EADDRINUSE
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v want %v", err, wantErr)
	}
	if len(tried) != 2 || tried[0] != LowportMin || tried[1] != LowportMax {
		t.Fatalf("tried %v, want [%d %d]", tried, LowportMin, LowportMax)
	}
}

func TestFirstAvailableLowportPicksPortInRange(t *testing.T) {
	port, err := FirstAvailableLowport(func(port int) error {
		if port < LowportMin || port > LowportMax {
			t.Fatalf("bind called with out of range port %d", port)
		}
		return nil
	})
	if err != nil || port < LowportMin || port > LowportMax {
		t.Fatalf("port=%d err=%v", port, err)
	}
}

func TestParsePositiveIntBase0AndTrailingJunk(t *testing.T) {
	n, err := ParsePositiveInt("0x10")
	if err != nil || n != 16 {
		t.Fatalf("0x10: n=%d err=%v want 16", n, err)
	}
	n, err = ParsePositiveInt("010")
	if err != nil || n != 8 {
		t.Fatalf("010: n=%d err=%v want 8", n, err)
	}
	if _, err := ParsePositiveInt("5abc"); err == nil {
		t.Fatal("5abc: expected error")
	}
	if _, err := ParsePositiveInt("0"); err == nil {
		t.Fatal("0: expected error")
	}
}

func TestParseIntAnyBase0(t *testing.T) {
	n, err := ParseIntAny("010")
	if err != nil || n != 8 {
		t.Fatalf("010: n=%d err=%v want 8", n, err)
	}
	n, err = ParseIntAny("0x10")
	if err != nil || n != 16 {
		t.Fatalf("0x10: n=%d err=%v want 16", n, err)
	}
	if _, err := ParseIntAny("10junk"); err == nil {
		t.Fatal("10junk: expected error")
	}
}

func TestParseSizeTMatchesUnsignedClassicParsing(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint64
	}{
		{value: "010", want: 8},
		{value: "0x10", want: 16},
		{value: "-1", want: ^uint64(0)},
	} {
		got, err := addrconfig.ParseSizeT(tc.value)
		if err != nil || got != tc.want {
			t.Errorf("ParseSizeT(%q)=%d,%v want %d", tc.value, got, err, tc.want)
		}
	}
	if _, err := addrconfig.ParseSizeT("10junk"); err == nil {
		t.Fatal("ParseSizeT accepted trailing junk")
	}
}

func TestRecvTimeoutFromSpecRejectsJunk(t *testing.T) {
	ok, err := parse.ParseSpec("UDP4-LISTEN:0,fork")
	if err != nil {
		t.Fatal(err)
	}
	d, err := RecvTimeout(mustDecodeAddress(t, ok))
	if err != nil || d != 0 {
		t.Fatalf("empty rcvtimeo d=%s err=%v", d, err)
	}
	bad, err := parse.ParseSpec("UDP4-LISTEN:0,fork,rcvtimeo=nope")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAddress(bad); err == nil {
		t.Fatal("expected rcvtimeo parse error")
	}
}

func TestBindHostAndDualStackFromPreparedConfig(t *testing.T) {
	s, err := parse.ParseSpec("TCP6-LISTEN:9,bind=[::1],sourceport=080,pf=ip6,ipv6-v6only=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := BindHost(config); got != "[::1]" {
		t.Fatalf("bind=%q", got)
	}
	if got := SourcePortText(config); got != "080" {
		t.Fatalf("sourceport=%q", got)
	}
	if got := ProtocolFamilyText(config); got != "ip6" {
		t.Fatalf("pf=%q", got)
	}
	if got := DualStackListenNetwork(config, "tcp6"); got != "tcp" {
		t.Fatalf("dual-stack network=%s", got)
	}

	s, err = parse.ParseSpec("TCP6-LISTEN:9,ipv6-v6only=1")
	if err != nil {
		t.Fatal(err)
	}
	config, err = decodeAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := DualStackListenNetwork(config, "tcp6"); got != "tcp6" {
		t.Fatalf("v6only network=%s", got)
	}
}
