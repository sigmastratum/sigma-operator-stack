//go:build windows

package main

import (
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	smtoAbortIfHung = 0x0002
	uiProbeTimeout  = 500
)

var (
	testUser32             = syscall.NewLazyDLL("user32.dll")
	testKernel32           = syscall.NewLazyDLL("kernel32.dll")
	testFindWindow         = testUser32.NewProc("FindWindowW")
	testSendMessageTimeout = testUser32.NewProc("SendMessageTimeoutW")
	testGetClipboardData   = testUser32.NewProc("GetClipboardData")
	testGlobalLock         = testKernel32.NewProc("GlobalLock")
	testGlobalUnlock       = testKernel32.NewProc("GlobalUnlock")
	testGlobalSize         = testKernel32.NewProc("GlobalSize")
)

func findEntrypointWindow(deadline time.Time) uintptr {
	for time.Now().Before(deadline) {
		hwnd, _, _ := testFindWindow.Call(
			uintptr(unsafe.Pointer(utf16(className))),
			uintptr(unsafe.Pointer(utf16(productName))),
		)
		if hwnd != 0 {
			return hwnd
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0
}

func sendResponsive(hwnd uintptr, event uint32, wParam uintptr) bool {
	var result uintptr
	ok, _, _ := testSendMessageTimeout.Call(
		hwnd,
		uintptr(event),
		wParam,
		0,
		smtoAbortIfHung,
		uiProbeTimeout,
		uintptr(unsafe.Pointer(&result)),
	)
	return ok != 0
}

func readClipboardText() (string, bool) {
	opened, _, _ := procOpenClipboard.Call(0)
	if opened == 0 {
		return "", false
	}
	defer procCloseClipboard.Call()
	handle, _, _ := testGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return "", false
	}
	size, _, _ := testGlobalSize.Call(handle)
	if size < 2 || size%2 != 0 {
		return "", false
	}
	pointer, _, _ := testGlobalLock.Call(handle)
	if pointer == 0 {
		return "", false
	}
	defer testGlobalUnlock.Call(handle)
	units := unsafe.Slice((*uint16)(unsafe.Pointer(pointer)), size/2)
	for index, unit := range units {
		if unit == 0 {
			return syscall.UTF16ToString(units[:index]), true
		}
	}
	return "", false
}

func TestCopyInstructionKeepsNativeWindowResponsive(t *testing.T) {
	candidate = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	done := make(chan int, 1)
	go func() { done <- run() }()
	hwnd := findEntrypointWindow(time.Now().Add(2 * time.Second))
	if hwnd == 0 {
		t.Fatal("native entrypoint window did not appear")
	}
	closed := false
	defer func() {
		if !closed {
			sendResponsive(hwnd, wmClose, 0)
		}
	}()
	if !sendResponsive(hwnd, wmCommand, buttonCopy) {
		t.Fatal("copy command blocked the native window")
	}

	deadline := time.Now().Add(3 * time.Second)
	matched := false
	for time.Now().Before(deadline) {
		if !sendResponsive(hwnd, 0, 0) {
			t.Fatal("native window stopped responding after copy")
		}
		if value, ok := readClipboardText(); ok && value == instruction {
			matched = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !matched {
		t.Fatal("clipboard did not contain the exact instruction")
	}

	// A temporarily occupied clipboard must not block the UI thread or admit
	// duplicate workers. The bounded worker reports failure asynchronously.
	opened, _, _ := procOpenClipboard.Call(0)
	if opened == 0 {
		t.Fatal("could not establish clipboard contention fixture")
	}
	if !sendResponsive(hwnd, wmCommand, buttonCopy) ||
		!sendResponsive(hwnd, wmCommand, buttonCopy) ||
		!sendResponsive(hwnd, 0, 0) {
		procCloseClipboard.Call()
		t.Fatal("native window blocked during clipboard contention")
	}
	time.Sleep(250 * time.Millisecond)
	procCloseClipboard.Call()
	deadline = time.Now().Add(2 * time.Second)
	for copyInProgress.Load() && time.Now().Before(deadline) {
		if !sendResponsive(hwnd, 0, 0) {
			t.Fatal("native window stopped responding after clipboard contention")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if copyInProgress.Load() {
		t.Fatal("bounded clipboard worker did not complete")
	}
	if !sendResponsive(hwnd, wmClose, 0) {
		t.Fatal("close command blocked after copy")
	}
	closed = true
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("native entrypoint exited with %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("native entrypoint did not exit")
	}
}
