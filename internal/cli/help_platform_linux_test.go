//go:build linux

package cli

import "testing"

func TestHelpPlatformVisibility(t *testing.T) {
	checkPlatformHelp(t,
		[]string{"ip-retopts", "retopts", "ipretopts", "ip-router-alert", "routeralert", "iprouteralert", "ipv6-recvdstopts", "recvdstopts", "ipv6-recvhopopts", "recvhopopts", "ip-recverr", "recverr", "iprecverr", "so-timestamp"},
		[]string{"ip-recvdstaddr", "recvdstaddr", "iprecvdstaddr", "ip-recvif", "recvif", "ipv6-recverr", "binary", "nopush"})
}
