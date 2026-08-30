//go:build !windows

package main

import (
	"errors"
	"os/exec"
	"time"
)

func runCommandInJob(command *exec.Cmd, timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		return false, errors.New("process timeout is invalid")
	}
	if err := command.Start(); err != nil {
		return false, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return false, err
	case <-timer.C:
		_ = command.Process.Kill()
		<-done
		return true, errors.New("bounded process reached its timeout")
	}
}
