//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"fmt"
	"os/exec"
)

func collectOracle(command *exec.Cmd, wait func() error, output *oracleBuffer) (string, error) {
	if command != nil && command.Process != nil && command.ProcessState == nil {
		_ = command.Process.Kill()
	}
	var waitErr error
	if wait != nil {
		waitErr = wait()
	}
	if output == nil {
		return "", waitErr
	}
	return output.String(), waitErr
}

func waitOracleContains(wait func() error, output *oracleBuffer, want []byte) error {
	if err := wait(); err != nil {
		return err
	}
	if !bytes.Contains(output.Bytes(), want) {
		return fmt.Errorf("oracle output missing %q:\n%s", want, output.String())
	}
	return nil
}

func echoWriteRead(conn *Conn, marker []byte) error {
	if _, err := conn.Write(marker); err != nil {
		return err
	}
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	if !bytes.Equal(buffer[:n], marker) {
		return fmt.Errorf("echo %q", buffer[:n])
	}
	return nil
}

func echoReadWrite(conn *Conn) ([]byte, error) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("peer data %q, %v", buffer[:n], err)
	}
	if _, err := conn.Write(buffer[:n]); err != nil {
		return buffer[:n], err
	}
	return buffer[:n], nil
}

func echoReadWriteExpect(conn *Conn, want string) error {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != want {
		return fmt.Errorf("peer data %q; want %q", buffer[:n], want)
	}
	_, err = conn.Write(buffer[:n])
	return err
}
