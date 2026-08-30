//go:build !windows

package main

import (
	"errors"
	"os"
)

func isReparse(_ string, info os.FileInfo) (bool, error) {
	return info.Mode()&os.ModeSymlink != 0, nil
}

func hasUnexpectedStreams(_ string) (bool, error) { return false, nil }

func currentProcessElevated() (bool, error) {
	return false, errors.New("Windows token API is unavailable")
}

func userAccountControlEnabled() (bool, error) {
	return false, errors.New("Windows registry API is unavailable")
}
