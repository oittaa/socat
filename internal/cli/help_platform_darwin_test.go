//go:build darwin

package cli

import "testing"

func TestHelpPlatformVisibility(t *testing.T) {
	checkPlatformHelp(t,
		[]string{"ip-recvdstaddr", "recvdstaddr", "iprecvdstaddr", "ip-recvif", "recvif", "ip-recvopts", "ipv6-recvrthdr", "so-timestamp", "nopush"},
		[]string{"ip-retopts", "retopts", "ipretopts", "ip-router-alert", "routeralert", "iprouteralert", "ipv6-recvdstopts", "recvdstopts", "ipv6-recvhopopts", "recvhopopts", "ip-recverr", "recverr", "iprecverr", "ipv6-recverr", "binary"})
}
