//go:build unix

package main

import "syscall"

// withUmask runs fn with the process umask set to mask, so files such as the
// signer socket are created with restrictive permissions from the start.
func withUmask(mask int, fn func() error) error {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	return fn()
}
