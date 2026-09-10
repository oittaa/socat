//go:build windows

package cli

import "testing"

func TestHelpPlatformVisibility(t *testing.T) {
	checkPlatformHelp(t,
		[]string{"binary", "text", "noinherit", "reuseaddr"},
		[]string{"ip-retopts", "retopts", "ipretopts", "ip-router-alert", "routeralert", "iprouteralert", "ipv6-recvdstopts", "recvdstopts", "ipv6-recvhopopts", "recvhopopts", "ip-recverr", "recverr", "iprecverr", "ip-recvdstaddr", "recvdstaddr", "iprecvdstaddr", "ip-recvif", "recvif", "ipv6-recverr", "so-timestamp", "nopush"})
}
