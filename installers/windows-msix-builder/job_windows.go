//go:build windows

package main

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
)

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInformationRecord struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IOInfo                jobObjectIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var (
	createJobObjectW        = kernel32.NewProc("CreateJobObjectW")
	setInformationJobObject = kernel32.NewProc("SetInformationJobObject")
	assignProcessToJob      = kernel32.NewProc("AssignProcessToJobObject")
)

func createKillOnCloseJob() (syscall.Handle, error) {
	handle, _, callErr := createJobObjectW.Call(0, 0)
	if handle == 0 {
		return 0, callErr
	}
	job := syscall.Handle(handle)
	limits := jobObjectExtendedLimitInformationRecord{}
	limits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	result, _, callErr := setInformationJobObject.Call(
		handle,
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		unsafe.Sizeof(limits),
	)
	if result == 0 {
		syscall.CloseHandle(job)
		return 0, callErr
	}
	return job, nil
}

func runCommandInJob(command *exec.Cmd, timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		return false, errors.New("process timeout is invalid")
	}
	job, err := createKillOnCloseJob()
	if err != nil {
		return false, err
	}
	jobOpen := true
	closeJob := func() error {
		if !jobOpen {
			return nil
		}
		jobOpen = false
		return syscall.CloseHandle(job)
	}
	defer closeJob()
	if err := command.Start(); err != nil {
		return false, err
	}
	assigned := false
	err = command.Process.WithHandle(func(processHandle uintptr) {
		result, _, _ := assignProcessToJob.Call(uintptr(job), processHandle)
		assigned = result != 0
	})
	if err != nil || !assigned {
		_ = command.Process.Kill()
		_ = command.Wait()
		if err != nil {
			return false, err
		}
		return false, errors.New("Python process could not be assigned to the kill-on-close job")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case waitErr := <-done:
		closeErr := closeJob()
		if waitErr != nil {
			return false, waitErr
		}
		return false, closeErr
	case <-timer.C:
		closeErr := closeJob()
		_ = command.Process.Kill()
		<-done
		if closeErr != nil {
			return true, closeErr
		}
		return true, errors.New("kill-on-close job reached its timeout")
	}
}
