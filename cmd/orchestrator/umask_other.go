//go:build !unix

package main

func withUmask(_ int, fn func() error) error {
	return fn()
}
