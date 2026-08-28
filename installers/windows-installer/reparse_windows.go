//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	shell32              = syscall.NewLazyDLL("shell32.dll")
	ole32                = syscall.NewLazyDLL("ole32.dll")
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	shGetKnownFolderPath = shell32.NewProc("SHGetKnownFolderPath")
	coTaskMemFree        = ole32.NewProc("CoTaskMemFree")
	regOpenKeyExW        = advapi32.NewProc("RegOpenKeyExW")
	regQueryValueExW     = advapi32.NewProc("RegQueryValueExW")
	regCloseKey          = advapi32.NewProc("RegCloseKey")
)

const (
	hkeyLocalMachine = 0x80000002
	keyQueryValue    = 0x0001
	regDword         = 4
)

var folderIDLocalAppData = syscall.GUID{
	Data1: 0xF1B32785,
	Data2: 0x6FBA,
	Data3: 0x4FCF,
	Data4: [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91},
}

func localAppDataKnownFolder() (string, uint32) {
	var path *uint16
	result, _, _ := shGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&folderIDLocalAppData)),
		0,
		0,
		uintptr(unsafe.Pointer(&path)),
	)
	if result != 0 {
		return "", uint32(result)
	}
	defer coTaskMemFree.Call(uintptr(unsafe.Pointer(path)))
	value := make([]uint16, 0, 260)
	for index := 0; index < 32768; index++ {
		character := *(*uint16)(unsafe.Add(unsafe.Pointer(path), uintptr(index*2)))
		if character == 0 {
			return syscall.UTF16ToString(value), 0
		}
		value = append(value, character)
	}
	return "", 0x8007007a
}

func currentProcessElevated() (bool, error) {
	token, errorValue := syscall.OpenCurrentProcessToken()
	if errorValue != nil {
		return false, errorValue
	}
	defer token.Close()
	var elevated uint32
	var returned uint32
	errorValue = syscall.GetTokenInformation(
		token,
		syscall.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)),
		uint32(unsafe.Sizeof(elevated)),
		&returned,
	)
	if errorValue != nil {
		return false, errorValue
	}
	if returned != uint32(unsafe.Sizeof(elevated)) {
		return false, syscall.EINVAL
	}
	return elevated != 0, nil
}

func userAccountControlEnabled() (bool, error) {
	subkey, errorValue := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`)
	if errorValue != nil {
		return false, errorValue
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
	name, errorValue := syscall.UTF16PtrFromString("EnableLUA")
	if errorValue != nil {
		return false, errorValue
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
