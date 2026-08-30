//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const fileAttributeReparsePoint = 0x00000400

const (
	hkeyLocalMachine       = 0x80000002
	keyQueryValue          = 0x0001
	regDword               = 4
	findStreamInfoStandard = 0
	errorHandleEOF         = syscall.Errno(38)
)

type win32FindStreamData struct {
	StreamSize int64
	StreamName [296]uint16
}

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	findFirstStream  = kernel32.NewProc("FindFirstStreamW")
	findNextStream   = kernel32.NewProc("FindNextStreamW")
	findClose        = kernel32.NewProc("FindClose")
	regOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	regQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	regCloseKey      = advapi32.NewProc("RegCloseKey")
)

func isReparse(path string, _ os.FileInfo) (bool, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := syscall.GetFileAttributes(pointer)
	if err != nil {
		return false, err
	}
	return attributes&fileAttributeReparsePoint != 0, nil
}

func hasUnexpectedStreams(path string) (bool, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	var data win32FindStreamData
	handle, _, callErr := findFirstStream.Call(
		uintptr(unsafe.Pointer(pointer)),
		findStreamInfoStandard,
		uintptr(unsafe.Pointer(&data)),
		0,
	)
	if handle == ^uintptr(0) {
		return false, callErr
	}
	defer findClose.Call(handle)
	for {
		if syscall.UTF16ToString(data.StreamName[:]) != "::$DATA" {
			return true, nil
		}
		result, _, nextErr := findNextStream.Call(handle, uintptr(unsafe.Pointer(&data)))
		if result != 0 {
			continue
		}
		if errno, ok := nextErr.(syscall.Errno); ok && errno == errorHandleEOF {
			return false, nil
		}
		return false, nextErr
	}
}

func currentProcessElevated() (bool, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()
	var elevated uint32
	var returned uint32
	err = syscall.GetTokenInformation(
		token,
		syscall.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)),
		uint32(unsafe.Sizeof(elevated)),
		&returned,
	)
	if err != nil {
		return false, err
	}
	if returned != uint32(unsafe.Sizeof(elevated)) {
		return false, syscall.EINVAL
	}
	return elevated != 0, nil
}

func userAccountControlEnabled() (bool, error) {
	subkey, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`)
	if err != nil {
		return false, err
	}
	var key syscall.Handle
	result, _, _ := regOpenKeyExW.Call(
		hkeyLocalMachine,
		uintptr(unsafe.Pointer(subkey)),
		0,
		keyQueryValue,
		uintptr(unsafe.Pointer(&key)),
	)
	if result != 0 {
		return false, syscall.Errno(result)
	}
	defer regCloseKey.Call(uintptr(key))
	name, err := syscall.UTF16PtrFromString("EnableLUA")
	if err != nil {
		return false, err
	}
	var valueType uint32
	var value uint32
	size := uint32(unsafe.Sizeof(value))
	result, _, _ = regQueryValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&value)),
		uintptr(unsafe.Pointer(&size)),
	)
	if result != 0 {
		return false, syscall.Errno(result)
	}
	if valueType != regDword || size != uint32(unsafe.Sizeof(value)) {
		return false, syscall.EINVAL
	}
	return value != 0, nil
}
