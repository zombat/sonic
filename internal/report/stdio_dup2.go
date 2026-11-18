//go:build darwin || freebsd || openbsd || netbsd || dragonfly

// Package report implements POSIX descriptor duplication via dup2 on Darwin and BSD systems.
package report

import "syscall"

func dupFD(oldfd, newfd int) error {
	return syscall.Dup2(oldfd, newfd)
}
