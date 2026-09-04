package main

import (
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	className               = "SOSStoreEntrypointWindow"
	buttonCopy              = 1001
	buttonClose             = 1002
	cfUnicodeText           = 13
	gmMoveable              = 0x0002
	wmCommand               = 0x0111
	wmClose                 = 0x0010
	wmDestroy               = 0x0002
	wmClipboardComplete     = 0x8001
	clipboardOpenAttempts   = 5
	clipboardOpenRetryDelay = 20 * time.Millisecond
	wsCaption               = 0x00C00000
	wsSysMenu               = 0x00080000
	wsMinimizeBox           = 0x00020000
	wsVisible               = 0x10000000
	wsChild                 = 0x40000000
	bsPushButton            = 0x00000000
	ssLeft                  = 0x00000000
	colorWindow             = 5
	cwUseDefault            = 0x80000000
	swShow                  = 5
	idcArrow                = 32512
	idError                 = -1
)

type point struct{ x, y int32 }

type message struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
	private uint32
}

type windowClass struct {
	size        uint32
	style       uint32
	wndProc     uintptr
	classExtra  int32
	windowExtra int32
	instance    uintptr
	icon        uintptr
	cursor      uintptr
	background  uintptr
	menuName    *uint16
	className   *uint16
	iconSmall   uintptr
}

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procRegisterClass    = user32.NewProc("RegisterClassExW")
	procCreateWindow     = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procLoadCursor       = user32.NewProc("LoadCursorW")
	procPostMessage      = user32.NewProc("PostMessageW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procSetWindowText    = user32.NewProc("SetWindowTextW")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procGlobalFree       = kernel32.NewProc("GlobalFree")
	copyButtonHandle     uintptr
	copyInProgress       atomic.Bool
)

func utf16(value string) *uint16 { return syscall.StringToUTF16Ptr(value) }

func lowWord(value uintptr) uint16 { return uint16(value & 0xffff) }

func openClipboardBounded(hwnd uintptr) bool {
	for attempt := 0; attempt < clipboardOpenAttempts; attempt++ {
		opened, _, _ := procOpenClipboard.Call(hwnd)
		if opened != 0 {
			return true
		}
		if attempt+1 < clipboardOpenAttempts {
			time.Sleep(clipboardOpenRetryDelay)
		}
	}
	return false
}

func copyInstruction(hwnd uintptr) bool {
	if !openClipboardBounded(hwnd) {
		return false
	}
	defer procCloseClipboard.Call()
	if emptied, _, _ := procEmptyClipboard.Call(); emptied == 0 {
		return false
	}
	encoded := syscall.StringToUTF16(instruction)
	size := uintptr(len(encoded) * 2)
	handle, _, _ := procGlobalAlloc.Call(gmMoveable, size)
	if handle == 0 {
		return false
	}
	pointer, _, _ := procGlobalLock.Call(handle)
	if pointer == 0 {
		procGlobalFree.Call(handle)
		return false
	}
	target := unsafe.Slice((*uint16)(unsafe.Pointer(pointer)), len(encoded))
	copy(target, encoded)
	procGlobalUnlock.Call(handle)
	stored, _, _ := procSetClipboardData.Call(cfUnicodeText, handle)
	if stored == 0 {
		procGlobalFree.Call(handle)
		return false
	}
	return true
}

func setControlText(hwnd uintptr, value string) {
	procSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(utf16(value))))
}

func copyInstructionWorker(hwnd uintptr) {
	// The clipboard is thread-affine. Keep OpenClipboard through CloseClipboard
	// on one locked worker thread so the window message loop remains responsive.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	copied := copyInstruction(hwnd)
	result := uintptr(0)
	if copied {
		result = 1
	}
	procPostMessage.Call(hwnd, wmClipboardComplete, result, 0)
}

func beginInstructionCopy(hwnd uintptr) {
	if !copyInProgress.CompareAndSwap(false, true) {
		return
	}
	procEnableWindow.Call(copyButtonHandle, 0)
	setControlText(copyButtonHandle, "Copying...")
	go copyInstructionWorker(hwnd)
}

func finishInstructionCopy(copied bool) {
	if copied {
		setControlText(copyButtonHandle, "Copied")
	} else {
		setControlText(copyButtonHandle, "Try copy again")
	}
	procEnableWindow.Call(copyButtonHandle, 1)
	copyInProgress.Store(false)
}

func windowProcedure(hwnd uintptr, event uint32, wParam, lParam uintptr) uintptr {
	switch event {
	case wmCommand:
		switch lowWord(wParam) {
		case buttonCopy:
			beginInstructionCopy(hwnd)
			return 0
		case buttonClose:
			procDestroyWindow.Call(hwnd)
			return 0
		}
	case wmClipboardComplete:
		finishInstructionCopy(wParam == 1)
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProc.Call(hwnd, uintptr(event), wParam, lParam)
	return result
}

func createControl(class, text string, style uintptr, x, y, width, height int32, parent, id, instance uintptr) uintptr {
	handle, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(utf16(class))),
		uintptr(unsafe.Pointer(utf16(text))),
		style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height),
		parent, id, instance, 0,
	)
	return handle
}

func run() int {
	if candidate == "unbound" {
		return 2
	}
	instance, _, _ := procGetModuleHandle.Call(0)
	cursor, _, _ := procLoadCursor.Call(0, idcArrow)
	class := windowClass{
		size:       uint32(unsafe.Sizeof(windowClass{})),
		wndProc:    syscall.NewCallback(windowProcedure),
		instance:   instance,
		cursor:     cursor,
		background: colorWindow + 1,
		className:  utf16(className),
	}
	registered, _, _ := procRegisterClass.Call(uintptr(unsafe.Pointer(&class)))
	if registered == 0 {
		return 2
	}
	hwnd, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(utf16(className))),
		uintptr(unsafe.Pointer(utf16(productName))),
		wsCaption|wsSysMenu|wsMinimizeBox,
		cwUseDefault, cwUseDefault, 620, 310,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return 2
	}
	copyButtonHandle = createControl("BUTTON", "Copy instruction", wsChild|wsVisible|bsPushButton, 280, 215, 150, 34, hwnd, buttonCopy, instance)
	if createControl("STATIC", statusText, wsChild|wsVisible|ssLeft, 28, 24, 540, 28, hwnd, 0, instance) == 0 ||
		createControl("STATIC", versionText, wsChild|wsVisible|ssLeft, 28, 58, 540, 22, hwnd, 0, instance) == 0 ||
		createControl("STATIC", "Open your project in Codex and ask:", wsChild|wsVisible|ssLeft, 28, 100, 540, 22, hwnd, 0, instance) == 0 ||
		createControl("STATIC", instruction, wsChild|wsVisible|ssLeft, 28, 128, 540, 52, hwnd, 0, instance) == 0 ||
		copyButtonHandle == 0 ||
		createControl("BUTTON", "Close", wsChild|wsVisible|bsPushButton, 445, 215, 120, 34, hwnd, buttonClose, instance) == 0 {
		procDestroyWindow.Call(hwnd)
		return 2
	}
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	var current message
	for {
		result, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&current)), 0, 0, 0)
		if int32(result) == idError {
			return 2
		}
		if result == 0 {
			return int(current.wParam)
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&current)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&current)))
	}
}

func main() { syscall.Exit(run()) }
