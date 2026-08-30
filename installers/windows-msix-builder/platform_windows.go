//go:build windows

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	driveFixed          = 3
	maxWindowsPathUTF16 = 32_768
)

type windowsGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	folderIDProgramFilesX86 = windowsGUID{
		Data1: 0x7c5a40ef,
		Data2: 0xa0fb,
		Data3: 0x4bfc,
		Data4: [8]byte{0x87, 0x4a, 0xc0, 0xf2, 0xe0, 0xb9, 0xfa, 0x8e},
	}
	shell32               = syscall.NewLazyDLL("shell32.dll")
	ole32                 = syscall.NewLazyDLL("ole32.dll")
	shGetKnownFolderPath  = shell32.NewProc("SHGetKnownFolderPath")
	coTaskMemFree         = ole32.NewProc("CoTaskMemFree")
	getVolumePathNameW    = kernel32.NewProc("GetVolumePathNameW")
	getDriveTypeW         = kernel32.NewProc("GetDriveTypeW")
	queryDosDeviceW       = kernel32.NewProc("QueryDosDeviceW")
	getVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
)

func windowsUTF16PointerToString(pointer *uint16) (string, error) {
	if pointer == nil {
		return "", errors.New("Windows API returned a null path")
	}
	buffer := (*[maxWindowsPathUTF16]uint16)(unsafe.Pointer(pointer))
	for index, value := range buffer {
		if value == 0 {
			if index == 0 {
				return "", errors.New("Windows API returned an empty path")
			}
			return syscall.UTF16ToString(buffer[:index]), nil
		}
	}
	return "", errors.New("Windows API returned an unterminated path")
}

func programFilesX86Path() (string, error) {
	var value *uint16
	result, _, _ := shGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&folderIDProgramFilesX86)),
		0,
		0,
		uintptr(unsafe.Pointer(&value)),
	)
	if result != 0 {
		return "", syscall.Errno(result)
	}
	defer coTaskMemFree.Call(uintptr(unsafe.Pointer(value)))
	path, err := windowsUTF16PointerToString(value)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) {
		return "", errors.New("Program Files x86 known folder is not a canonical local path")
	}
	return path, nil
}

func requireLocalFixedNTFS(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) {
		return errors.New("path is not a canonical local Windows path")
	}
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	volumePath := make([]uint16, maxWindowsPathUTF16)
	result, _, callErr := getVolumePathNameW.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		uintptr(unsafe.Pointer(&volumePath[0])),
		uintptr(len(volumePath)),
	)
	if result == 0 {
		return callErr
	}
	root := syscall.UTF16ToString(volumePath)
	if root == "" || !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) {
		return errors.New("volume root is not local")
	}
	rootPointer, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	driveType, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(rootPointer)))
	if driveType != driveFixed {
		return errors.New("volume is not a fixed local drive")
	}
	volume := filepath.VolumeName(root)
	if len(volume) != 2 || volume[1] != ':' {
		return errors.New("volume is not a canonical drive-letter device")
	}
	deviceName, err := syscall.UTF16PtrFromString(volume)
	if err != nil {
		return err
	}
	deviceTarget := make([]uint16, maxWindowsPathUTF16)
	length, _, callErr := queryDosDeviceW.Call(
		uintptr(unsafe.Pointer(deviceName)),
		uintptr(unsafe.Pointer(&deviceTarget[0])),
		uintptr(len(deviceTarget)),
	)
	if length == 0 {
		return callErr
	}
	if target := syscall.UTF16ToString(deviceTarget); !strings.HasPrefix(target, `\Device\HarddiskVolume`) {
		return errors.New("drive is mapped, substituted, or not a fixed disk volume")
	}
	filesystem := make([]uint16, 64)
	result, _, callErr = getVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rootPointer)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&filesystem[0])),
		uintptr(len(filesystem)),
	)
	if result == 0 {
		return callErr
	}
	if !strings.EqualFold(syscall.UTF16ToString(filesystem), "NTFS") {
		return errors.New("volume filesystem is not NTFS")
	}
	return nil
}
