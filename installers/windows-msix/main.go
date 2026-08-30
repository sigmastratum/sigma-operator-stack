package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var candidate = "unbound"

func closedPythonEnvironment(packageRoot string) []string {
	blocked := map[string]bool{
		"PYTHONHOME": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
		"PYTHONUSERBASE": true, "PYTHONINSPECT": true,
		"PYTHONDONTWRITEBYTECODE": true, "PYTHONPYCACHEPREFIX": true,
	}
	environment := make([]string, 0, len(os.Environ())+3)
	for _, item := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(item, "=", 2)[0])
		if !blocked[name] {
			environment = append(environment, item)
		}
	}
	return append(environment,
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONNOUSERSITE=1",
		"PYTHONSAFEPATH=1",
		"PYTHONPATH="+filepath.Join(packageRoot, "runtime", "Lib", "site-packages"),
	)
}

func translated(arguments []string) ([]string, error) {
	if len(arguments) == 0 {
		return nil, fmt.Errorf("usage: sos install|update|remove|COMMAND [PATH]")
	}
	if arguments[0] == "install" {
		if len(arguments) != 2 {
			return nil, fmt.Errorf("usage: sos install PROJECT")
		}
		return []string{"-B", "-m", "sos", "init", "--with-codex", arguments[1]}, nil
	}
	if arguments[0] == "update" || arguments[0] == "remove" {
		if len(arguments) != 2 {
			return nil, fmt.Errorf("usage: sos %s PROJECT", arguments[0])
		}
		return []string{"-B", "-m", "sos", "setup", arguments[0], "codex", arguments[1]}, nil
	}
	return append([]string{"-B", "-m", "sos"}, arguments...), nil
}

func run() int {
	if candidate == "unbound" {
		fmt.Fprintln(os.Stderr, "SOS_MSIX_LAUNCHER_UNBOUND")
		return 2
	}
	arguments, errorValue := translated(os.Args[1:])
	if errorValue != nil {
		fmt.Fprintln(os.Stderr, errorValue)
		return 2
	}
	executable, errorValue := os.Executable()
	if errorValue != nil {
		fmt.Fprintln(os.Stderr, "SOS_MSIX_PACKAGE_LOCATION_UNAVAILABLE")
		return 2
	}
	packageRoot := filepath.Dir(executable)
	python := filepath.Join(packageRoot, "runtime", "python.exe")
	if info, errorValue := os.Lstat(python); errorValue != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(os.Stderr, "SOS_MSIX_RUNTIME_INVALID")
		return 2
	}
	command := exec.Command(python, arguments...)
	command.Env = closedPythonEnvironment(packageRoot)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if errorValue := command.Run(); errorValue != nil {
		if exit, ok := errorValue.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "SOS_MSIX_RUNTIME_START_FAILED")
		return 2
	}
	return 0
}

func main() { os.Exit(run()) }
