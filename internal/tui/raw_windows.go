//go:build windows

// Package tui provides a no-op raw terminal input fallback for Windows consoles.
package tui

import "io"

func enableRawInput(io.Reader) func() {
	return func() {}
}
