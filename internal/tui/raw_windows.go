//go:build windows

package tui

import "io"

func enableRawInput(io.Reader) func() {
	return func() {}
}
