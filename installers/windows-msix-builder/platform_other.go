//go:build !windows

package main

import "errors"

func programFilesX86Path() (string, error) {
	return "", errors.New("Windows Known Folder API is unavailable")
}

func requireLocalFixedNTFS(_ string) error {
	return errors.New("Windows volume APIs are unavailable")
}
