//go:build !windows

package tui

import (
	"io"
	"os"
	"os/exec"
	"strings"
)

func enableRawInput(in io.Reader) func() {
	f, ok := in.(*os.File)
	if !ok {
		return func() {}
	}
	info, err := f.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) == 0 {
		return func() {}
	}
	gCmd := exec.Command("stty", "-g")
	gCmd.Stdin = f
	saved, err := gCmd.Output()
	if err != nil {
		return func() {}
	}
	state := strings.TrimSpace(string(saved))
	rCmd := exec.Command("stty", "-icanon", "-echo", "min", "1")
	rCmd.Stdin = f
	if err := rCmd.Run(); err != nil {
		return func() {}
	}
	return func() {
		rest := exec.Command("stty", state)
		rest.Stdin = f
		_ = rest.Run()
	}
}
