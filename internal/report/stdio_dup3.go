//go:build linux

// Package report implements POSIX descriptor duplication on Linux architectures
// where legacy dup2 is absent on arm64/riscv64 in favor of dup3.
package report

import "syscall"

func dupFD(oldfd, newfd int) error {
	if oldfd == newfd {
		return nil
	}
	return syscall.Dup3(oldfd, newfd, 0)
}
