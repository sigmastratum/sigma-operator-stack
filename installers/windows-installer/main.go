//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	version        = "0.1.0a2"
	pythonVersion  = "3.12.14"
	uvVersion      = "0.12.6"
	uvDigest       = "965816e654d8fac650b282345c89c1daff16a0cfe45e9d2d2a8f5af3fed466a4"
	maxOutputBytes = 64 * 1024
)

var candidate = "unbound"

const ownerMarker = ".sos-environment-owner-v1"

type refusal struct{ code, problem, fix string }

func (value refusal) Error() string   { return value.code + ": " + value.problem }
func fail(code, problem string) error { return refusal{code: code, problem: problem} }
func failWithFix(code, problem, fix string) error {
	return refusal{code: code, problem: problem, fix: fix}
}

func digest(path string) (string, error) {
	handle, errorValue := os.Open(path)
	if errorValue != nil {
		return "", errorValue
	}
	defer handle.Close()
	hash := sha256.New()
	if _, errorValue = io.Copy(hash, io.LimitReader(handle, 256*1024*1024+1)); errorValue != nil {
		return "", errorValue
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func regularNoReparse(path string) error {
	info, errorValue := os.Lstat(path)
	if errorValue != nil {
		return errorValue
	}
	if !info.Mode().IsRegular() {
		return fail("SOS_ALPHA_BUNDLE_OBJECT_INVALID", "required artifact is not a regular file")
	}
	reparse, errorValue := hasReparsePoint(path)
	if errorValue != nil || reparse {
		return fail("SOS_ALPHA_BUNDLE_OBJECT_INVALID", "required artifact is a reparse point or cannot be verified")
	}
	return nil
}
func ensureDirectoryNoReparse(path string) error {
	info, errorValue := os.Lstat(path)
	if errors.Is(errorValue, os.ErrNotExist) {
		return os.MkdirAll(path, 0700)
	}
	if errorValue != nil || !info.IsDir() {
		return fail("SOS_ALPHA_RUNTIME_COLLISION", "managed runtime root is not a directory")
	}
	reparse, errorValue := hasReparsePoint(path)
	if errorValue != nil || reparse {
		return fail("SOS_ALPHA_RUNTIME_COLLISION", "managed runtime root is a reparse point or cannot be verified")
	}
	return nil
}

func currentUserBinding() (string, error) {
	token, errorValue := syscall.OpenCurrentProcessToken()
	if errorValue != nil {
		return "", fail("SOS_ALPHA_OWNER_IDENTITY_UNAVAILABLE", "current Windows user identity cannot be verified")
	}
	defer token.Close()
	user, errorValue := token.GetTokenUser()
	if errorValue != nil {
		return "", fail("SOS_ALPHA_OWNER_IDENTITY_UNAVAILABLE", "current Windows user identity cannot be verified")
	}
	sid, errorValue := user.User.Sid.String()
	if errorValue != nil || sid == "" {
		return "", fail("SOS_ALPHA_OWNER_IDENTITY_UNAVAILABLE", "current Windows user identity cannot be verified")
	}
	sum := sha256.Sum256([]byte("sos-managed-environment-owner-v1\x00" + sid))
	return hex.EncodeToString(sum[:]), nil
}

func ensureOwnedEnvironment(path, binding string, create bool) error {
	info, errorValue := os.Lstat(path)
	if errors.Is(errorValue, os.ErrNotExist) {
		if !create {
			return fail("SOS_ALPHA_MANAGED_ENVIRONMENT_MISSING", "SOS-managed installation environment is unavailable")
		}
		temporary := fmt.Sprintf("%s.new-%d", path, os.Getpid())
		if errorValue = os.Mkdir(temporary, 0700); errorValue != nil {
			return fail("SOS_ALPHA_MANAGED_ENVIRONMENT_CREATE_FAILED", "SOS-managed installation environment could not be created")
		}
		marker := filepath.Join(temporary, ownerMarker)
		if errorValue = os.WriteFile(marker, []byte(binding+"\n"), 0600); errorValue != nil {
			_ = os.RemoveAll(temporary)
			return fail("SOS_ALPHA_MANAGED_ENVIRONMENT_CREATE_FAILED", "SOS-managed installation environment owner binding could not be created")
		}
		if errorValue = os.Rename(temporary, path); errorValue == nil {
			return nil
		}
		_ = os.RemoveAll(temporary)
		info, errorValue = os.Lstat(path)
	}
	if errorValue != nil || !info.IsDir() {
		return fail("SOS_ALPHA_MANAGED_ENVIRONMENT_FOREIGN", "SOS-managed installation environment is unavailable or foreign")
	}
	reparse, errorValue := hasReparsePoint(path)
	if errorValue != nil || reparse {
		return fail("SOS_ALPHA_MANAGED_ENVIRONMENT_FOREIGN", "SOS-managed installation environment is a reparse point or cannot be verified")
	}
	payload, errorValue := os.ReadFile(filepath.Join(path, ownerMarker))
	if errorValue != nil || string(payload) != binding+"\n" {
		return fail("SOS_ALPHA_MANAGED_ENVIRONMENT_FOREIGN", "SOS-managed installation environment owner binding does not match the current user")
	}
	return nil
}

func userStorageFailure(errorValue error) error {
	if errors.Is(errorValue, os.ErrPermission) || errors.Is(errorValue, syscall.ERROR_ACCESS_DENIED) {
		return fail("SOS_ALPHA_USER_STORAGE_ACCESS_DENIED", "current Windows user cannot write the canonical Local AppData directory")
	}
	return fail("SOS_ALPHA_USER_STORAGE_UNAVAILABLE", "canonical Local AppData admission failed")
}

func admitUserStorage(path string) error {
	nonce := make([]byte, 16)
	if _, errorValue := rand.Read(nonce); errorValue != nil {
		return fail("SOS_ALPHA_USER_STORAGE_UNAVAILABLE", "user-storage admission nonce could not be generated")
	}
	probe := filepath.Join(path, ".sos-storage-probe-"+hex.EncodeToString(nonce))
	marker := filepath.Join(probe, "marker")
	payload := []byte("sos-user-storage-admission-v1\n")
	if errorValue := os.Mkdir(probe, 0700); errorValue != nil {
		return userStorageFailure(errorValue)
	}
	cleanup := func() error {
		if errorValue := os.Remove(marker); errorValue != nil && !errors.Is(errorValue, os.ErrNotExist) {
			return errorValue
		}
		return os.Remove(probe)
	}
	if errorValue := os.WriteFile(marker, payload, 0600); errorValue != nil {
		if cleanupError := cleanup(); cleanupError != nil {
			return fail("SOS_ALPHA_USER_STORAGE_CLEANUP_FAILED", "user-storage admission marker could not be removed")
		}
		return userStorageFailure(errorValue)
	}
	observed, errorValue := os.ReadFile(marker)
	if errorValue != nil || !bytes.Equal(observed, payload) {
		if cleanupError := cleanup(); cleanupError != nil {
			return fail("SOS_ALPHA_USER_STORAGE_CLEANUP_FAILED", "user-storage admission marker could not be removed")
		}
		if errorValue != nil {
			return userStorageFailure(errorValue)
		}
		return fail("SOS_ALPHA_USER_STORAGE_UNAVAILABLE", "user-storage admission marker did not round-trip")
	}
	if errorValue = cleanup(); errorValue != nil {
		return fail("SOS_ALPHA_USER_STORAGE_CLEANUP_FAILED", "user-storage admission marker could not be removed")
	}
	return nil
}
func requireDirectoryNoReparse(path string) error {
	info, errorValue := os.Lstat(path)
	if errorValue != nil || !info.IsDir() {
		return fail("SOS_ALPHA_MANAGED_RUNTIME_MISSING", "managed runtime directory is unavailable")
	}
	reparse, errorValue := hasReparsePoint(path)
	if errorValue != nil || reparse {
		return fail("SOS_ALPHA_RUNTIME_COLLISION", "managed runtime directory is a reparse point or cannot be verified")
	}
	return nil
}
func copyExact(source, destination string) error {
	if observed, errorValue := digest(destination); errorValue == nil {
		if observed == uvDigest {
			return nil
		}
		return fail("SOS_ALPHA_UV_BINDING_INVALID", "managed uv differs from the checked bundle")
	}
	temporary := destination + ".new"
	_ = os.Remove(temporary)
	reader, errorValue := os.Open(source)
	if errorValue != nil {
		return errorValue
	}
	defer reader.Close()
	writer, errorValue := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errorValue != nil {
		return errorValue
	}
	_, copyError := io.Copy(writer, reader)
	closeError := writer.Close()
	if copyError != nil || closeError != nil {
		_ = os.Remove(temporary)
		if copyError != nil {
			return copyError
		}
		return closeError
	}
	if errorValue = os.Rename(temporary, destination); errorValue != nil {
		_ = os.Remove(temporary)
		return errorValue
	}
	return nil
}
func closedEnvironment(runtimeRoot, pythonRoot string) []string {
	keys := []string{"COMSPEC", "LOCALAPPDATA", "PATH", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE"}
	environment := make([]string, 0, len(keys)+5)
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	return append(
		environment,
		"UV_NO_CONFIG=1",
		"UV_NO_CACHE=1",
		"UV_PYTHON_INSTALL_DIR="+pythonRoot,
		"UV_TOOL_DIR="+filepath.Join(runtimeRoot, "tools"),
		"UV_TOOL_BIN_DIR="+filepath.Join(runtimeRoot, "bin"),
	)
}
func run(executable string, arguments, environment []string, capture bool) (int, string, error) {
	command := exec.Command(executable, arguments...)
	command.Env = environment
	command.Stdin = os.Stdin
	command.Stderr = os.Stderr
	var output bytes.Buffer
	if capture {
		command.Stdout = &output
	} else {
		command.Stdout = os.Stdout
	}
	errorValue := command.Run()
	if output.Len() > maxOutputBytes {
		return 2, "", fail("SOS_ALPHA_OUTPUT_LIMIT", "subprocess output exceeded the fixed limit")
	}
	if errorValue == nil {
		return 0, strings.TrimSpace(output.String()), nil
	}
	var exitError *exec.ExitError
	if errors.As(errorValue, &exitError) {
		return exitError.ExitCode(), strings.TrimSpace(output.String()), nil
	}
	return 2, "", errorValue
}

func runChecked(executable string, arguments, environment []string, capture bool, exitCode, exitProblem string) (int, string, error) {
	status, output, errorValue := run(executable, arguments, environment, capture)
	if errorValue != nil {
		return 2, "", fail("SOS_ALPHA_SUBPROCESS_START_FAILED", "a fixed native bootstrap subprocess could not be started")
	}
	if status != 0 {
		return status, output, fail(exitCode, exitProblem)
	}
	return status, output, nil
}
func findPython(uv string, environment []string) (string, bool, error) {
	status, output, errorValue := run(uv, []string{"python", "find", "--no-config", "--managed-python", "--no-python-downloads", pythonVersion}, environment, true)
	if errorValue != nil || status != 0 || output == "" {
		return "", false, errorValue
	}
	if strings.ContainsAny(output, "\r\n") || !filepath.IsAbs(output) {
		return "", false, fail("SOS_ALPHA_MANAGED_PYTHON_INVALID", "managed Python binding is not one absolute path")
	}
	if errorValue = regularNoReparse(output); errorValue != nil {
		return "", false, fail("SOS_ALPHA_MANAGED_PYTHON_INVALID", "managed Python is not a verified regular file")
	}
	return output, true, nil
}
func usage() error {
	return fail("SOS_ALPHA_ARGUMENTS_INVALID", "usage: SOS-Installer.exe install|update|remove|test [PROJECT]")
}
func execute() (int, error) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		short := candidate
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Printf("SOS Windows Installer %s (%s)\n", version, short)
		return 0, nil
	}
	if len(os.Args) < 2 || len(os.Args) > 3 {
		return 2, usage()
	}
	mode := strings.ToLower(os.Args[1])
	if mode != "install" && mode != "update" && mode != "remove" && mode != "test" {
		return 2, usage()
	}
	elevated, errorValue := currentProcessElevated()
	if errorValue != nil {
		return 2, failWithFix("SOS_ALPHA_ELEVATION_STATE_UNAVAILABLE", "Windows process elevation state cannot be verified", "Use a supported ordinary Windows user session; do not weaken this check.")
	}
	uacEnabled, errorValue := userAccountControlEnabled()
	if errorValue != nil {
		return 2, failWithFix("SOS_ALPHA_ELEVATION_STATE_UNAVAILABLE", "Windows UAC state cannot be verified", "Use a supported ordinary Windows user session; do not weaken this check.")
	}
	if !uacEnabled {
		return 2, failWithFix("SOS_ALPHA_UAC_DISABLED_UNSUPPORTED", "Windows User Account Control is disabled", "Enable UAC and restart Windows, or use a supported Windows host.")
	}
	if elevated {
		return 2, failWithFix("SOS_ALPHA_ELEVATION_FORBIDDEN", "SOS is running with an elevated Windows token", "Close this window and start SOS by ordinary double-click or from a non-Administrator terminal.")
	}
	project := "."
	if len(os.Args) == 3 {
		project = os.Args[2]
	}
	project, errorValue = filepath.Abs(project)
	if errorValue != nil {
		return 2, fail("SOS_ALPHA_PROJECT_INVALID", "project path cannot be normalized")
	}
	executable, errorValue := os.Executable()
	if errorValue != nil {
		return 2, errorValue
	}
	bundle := filepath.Dir(executable)
	uvSource := filepath.Join(bundle, "uv.exe")
	if errorValue = regularNoReparse(uvSource); errorValue != nil {
		return 2, fail("SOS_ALPHA_UV_BUNDLE_INVALID", "checked uv bootstrap is missing or unsafe")
	}
	if observed, digestError := digest(uvSource); digestError != nil || observed != uvDigest {
		return 2, fail("SOS_ALPHA_UV_CHECKSUM_MISMATCH", "checked uv bootstrap digest does not match")
	}
	environmentLocalAppData := os.Getenv("LOCALAPPDATA")
	localAppData, knownFolderHRESULT := localAppDataKnownFolder()
	if knownFolderHRESULT != 0 || localAppData == "" || !filepath.IsAbs(localAppData) {
		return 2, fail("SOS_ALPHA_LOCALAPPDATA_KNOWN_FOLDER_UNAVAILABLE", "Windows Known Folder Local AppData is unavailable")
	}
	if environmentLocalAppData == "" || !filepath.IsAbs(environmentLocalAppData) ||
		!strings.EqualFold(filepath.Clean(environmentLocalAppData), filepath.Clean(localAppData)) {
		return 2, fail("SOS_ALPHA_LOCALAPPDATA_MISMATCH", "LOCALAPPDATA does not match the Windows Known Folder binding")
	}
	if reparse, reparseError := hasReparsePoint(localAppData); reparseError != nil || reparse {
		return 2, fail("SOS_ALPHA_USER_STORAGE_UNAVAILABLE", "canonical Local AppData is a reparse point or cannot be verified")
	}
	if errorValue = admitUserStorage(localAppData); errorValue != nil {
		return 2, errorValue
	}
	ownerBinding, errorValue := currentUserBinding()
	if errorValue != nil {
		return 2, errorValue
	}
	managedRoot := filepath.Join(localAppData, "SigmaOperatorStackEnvironment-"+ownerBinding[:16])
	if errorValue = ensureOwnedEnvironment(managedRoot, ownerBinding, mode == "install" || mode == "update"); errorValue != nil {
		return 2, errorValue
	}
	runtimeRoot := filepath.Join(managedRoot, "environment")
	bootstrap := filepath.Join(runtimeRoot, "bootstrap")
	pythonRoot := filepath.Join(runtimeRoot, "python")
	directories := []string{managedRoot, runtimeRoot, bootstrap, pythonRoot, filepath.Join(runtimeRoot, "tools"), filepath.Join(runtimeRoot, "bin")}
	for _, directory := range directories {
		if mode == "remove" || mode == "test" {
			errorValue = requireDirectoryNoReparse(directory)
		} else {
			errorValue = ensureDirectoryNoReparse(directory)
		}
		if errorValue != nil {
			return 2, errorValue
		}
	}
	uv := filepath.Join(bootstrap, "uv-"+uvVersion+".exe")
	if mode == "remove" || mode == "test" {
		if errorValue = regularNoReparse(uv); errorValue != nil {
			return 2, fail("SOS_ALPHA_UV_BINDING_INVALID", "managed uv is unavailable or unsafe")
		}
		if observed, digestError := digest(uv); digestError != nil || observed != uvDigest {
			return 2, fail("SOS_ALPHA_UV_BINDING_INVALID", "managed uv differs from the checked bundle")
		}
	} else if errorValue = copyExact(uvSource, uv); errorValue != nil {
		return 2, errorValue
	}
	environment := closedEnvironment(runtimeRoot, pythonRoot)
	python, found, errorValue := findPython(uv, environment)
	if errorValue != nil {
		return 2, errorValue
	}
	if !found {
		if mode == "remove" || mode == "test" {
			return 2, fail("SOS_ALPHA_MANAGED_PYTHON_MISSING", "this operation cannot acquire a runtime")
		}
		fmt.Printf("SOS acquisition: installing pinned managed Python %s.\n", pythonVersion)
		status, _, runError := runChecked(
			uv,
			[]string{"--native-tls", "--no-cache", "python", "install", "--no-config", "--no-progress", "--no-registry", "--install-dir", pythonRoot, pythonVersion},
			environment,
			false,
			"SOS_ALPHA_PYTHON_ACQUISITION_FAILED",
			"verified managed Python acquisition failed",
		)
		if runError != nil {
			return status, runError
		}
		python, found, errorValue = findPython(uv, environment)
		if errorValue != nil || !found {
			return 2, fail("SOS_ALPHA_MANAGED_PYTHON_MISSING", "pinned managed runtime was not admitted")
		}
	}
	arguments := []string{filepath.Join(bundle, "start-sos-alpha"), "--uv", uv, "--mode", mode, project}
	if mode == "test" {
		arguments = []string{filepath.Join(bundle, "native-smoke"), "--uv", uv, project}
	}
	status, _, errorValue := run(python, arguments, environment, false)
	if errorValue != nil || status != 0 {
		return status, errorValue
	}
	if mode == "remove" {
		expected := filepath.Join(localAppData, "SigmaOperatorStackEnvironment-"+ownerBinding[:16], "environment")
		if runtimeRoot != expected {
			return 2, fail("SOS_ALPHA_RUNTIME_REMOVE_REFUSED", "managed runtime root is not exact")
		}
		if reparse, reparseError := hasReparsePoint(runtimeRoot); reparseError != nil || reparse {
			return 2, fail("SOS_ALPHA_RUNTIME_REMOVE_REFUSED", "managed runtime root is unsafe")
		}
		if errorValue = os.RemoveAll(runtimeRoot); errorValue != nil {
			return 2, errorValue
		}
	}
	return 0, nil
}
func main() {
	status, errorValue := execute()
	if errorValue != nil {
		if typed, ok := errorValue.(refusal); ok {
			fmt.Fprintf(os.Stderr, "SOS alpha setup stopped.\nCode: %s\nProblem: %s\n", typed.code, typed.problem)
			if typed.fix != "" {
				fmt.Fprintf(os.Stderr, "Fix: %s\n", typed.fix)
			}
		} else {
			fmt.Fprintln(os.Stderr, "SOS alpha setup stopped.\nCode: SOS_ALPHA_INSTALLER_FAILED\nProblem: bounded native installer operation failed.")
		}
	}
	os.Exit(status)
}
