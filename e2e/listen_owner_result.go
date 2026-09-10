//go:build e2e

package e2e

import "fmt"

// listenOwnerFromC maps socat_e2e_pid_listens. n is the C return: -1 on
// allocation failure, 0 if the pid does not listen, >0 if it does.
// errno is only meaningful when n < 0; a leftover errno from an ignored
// descriptor lookup must not reject a later successful find.
func listenOwnerFromC(n int, errno error) (bool, error) {
	if n < 0 {
		if errno != nil {
			return false, errno
		}
		return false, fmt.Errorf("proc_pidinfo: memory allocation failed")
	}
	return n > 0, nil
}
