//go:build windows

package main

import "syscall"

func hasReparsePoint(path string) (bool, error) {
	pointer, errorValue := syscall.UTF16PtrFromString(path)
	if errorValue != nil {
		return false, errorValue
	}
	attributes, errorValue := syscall.GetFileAttributes(pointer)
	if errorValue != nil {
		return false, errorValue
	}
	return attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}
