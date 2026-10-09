

package tool

import (
	"errors"
	"os"
	"os/exec"
)

func startPTY(_ *exec.Cmd, _, _ int) (*os.File, error) {
	return nil, errors.New("interactive shell (PTY) is not supported on this platform")
}

func ptySupported() bool { return false }
