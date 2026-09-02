package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

var (
	candidate       = "unbound"
	tree            = "unbound"
	inputLockDigest = "unbound"
)

const (
	buildMarkerName     = ".sos-msix-builder-owned-v1"
	buildMarkerContent  = "sos-windows-msix-builder-owned-v1\n"
	maxPacketFiles      = 25_000
	maxPacketBytes      = int64(3 * 1024 * 1024 * 1024)
	maxPacketSingleFile = int64(1024 * 1024 * 1024)
	maxProcessOutput    = 512 * 1024
)

type buildError struct {
	code    string
	problem string
	buildID string
	cause   error
}

func (failure *buildError) Error() string {
	if failure.cause == nil {
		return failure.problem
	}
	return failure.problem + ": " + failure.cause.Error()
}

func stop(code string, problem string, cause error) *buildError {
	return &buildError{code: code, problem: problem, cause: cause}
}

func sha256File(path string) (string, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, input); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func bindingForBytes(path string, data []byte) fileBinding {
	digest := sha256.Sum256(data)
	return fileBinding{Path: path, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data))}
}

func classifyFirstStream(isDirectory bool, streamName string, observedErr error) (bool, error) {
	if observedErr != nil {
		if isDirectory && errors.Is(observedErr, syscall.Errno(38)) {
			return false, nil
		}
		return false, observedErr
	}
	return streamName != "::$DATA", nil
}

func verifyRegularFile(path string, binding fileBinding) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != binding.Size {
		return errors.New("bound file type or size is invalid")
	}
	reparse, err := isReparse(path, info)
	if err != nil || reparse {
		return errors.New("bound file is a link or reparse object")
	}
	unexpectedStreams, err := hasUnexpectedStreams(path)
	if err != nil || unexpectedStreams {
		return errors.New("bound file contains an alternate data stream")
	}
	digest, err := sha256File(path)
	if err != nil || digest != binding.SHA256 {
		return errors.New("bound file digest is invalid")
	}
	return nil
}

func verifyExistingPathComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil || absolute != filepath.Clean(absolute) {
		return errors.New("path is not absolute and canonical")
	}
	volume := filepath.VolumeName(absolute)
	if runtime.GOOS == "windows" && (volume == "" || strings.HasPrefix(volume, `\\`)) {
		return errors.New("path is not on a local Windows volume")
	}
	current := string(os.PathSeparator)
	remainder := strings.TrimPrefix(absolute, current)
	if volume != "" {
		current = volume + string(os.PathSeparator)
		remainder = strings.TrimPrefix(absolute, current)
	}
	if remainder == "" {
		return nil
	}
	for _, component := range strings.Split(remainder, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		reparse, err := isReparse(current, info)
		if err != nil || reparse || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a link or reparse component")
		}
		unexpectedStreams, err := hasUnexpectedStreams(current)
		if err != nil || unexpectedStreams {
			return errors.New("path contains an alternate data stream")
		}
	}
	return nil
}

func relativeFromRoot(root string, value string) (string, error) {
	relative, err := filepath.Rel(root, value)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("object escapes its admitted root")
	}
	return filepath.ToSlash(relative), nil
}

func verifyPacket(root string, manifest *packetManifest, executable string, manifestBinding fileBinding) error {
	expectedFiles := make(map[string]fileBinding, len(manifest.Files)+1)
	expectedFolded := make(map[string]string, len(manifest.Files)+1)
	expectedDirectories := map[string]bool{".": true}
	for _, file := range manifest.Files {
		expectedFiles[file.Path] = file
		expectedFolded[strings.ToLower(file.Path)] = file.Path
		parts := strings.Split(file.Path, "/")
		for index := 1; index < len(parts); index++ {
			expectedDirectories[strings.Join(parts[:index], "/")] = true
		}
	}
	expectedFiles[packetManifestName] = manifestBinding
	expectedFolded[strings.ToLower(packetManifestName)] = packetManifestName
	var actualFileCount int
	var actualBytes int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative := "."
		if path != root {
			var err error
			relative, err = relativeFromRoot(root, path)
			if err != nil {
				return err
			}
			if safe, err := safeRelativePath(relative); err != nil || safe != relative {
				return errors.New("packet contains an unsafe path")
			}
		}
		reparse, err := isReparse(path, info)
		if err != nil || reparse || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("packet contains a link or reparse object")
		}
		unexpectedStreams, err := hasUnexpectedStreams(path)
		if err != nil || unexpectedStreams {
			return errors.New("packet contains an alternate data stream")
		}
		if info.IsDir() {
			if !expectedDirectories[relative] {
				return errors.New("packet contains an unlisted directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("packet contains a non-regular object")
		}
		spelling, ok := expectedFolded[strings.ToLower(relative)]
		if !ok || spelling != relative {
			return errors.New("packet contains an unlisted or case-drifted file")
		}
		actualFileCount++
		if info.Size() < 0 || actualBytes > maxPacketBytes-info.Size() {
			return errors.New("packet exceeds its bounded byte inventory")
		}
		actualBytes += info.Size()
		if actualFileCount > maxPacketFiles {
			return errors.New("packet exceeds its bounded inventory")
		}
		if err := verifyRegularFile(path, expectedFiles[relative]); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if actualFileCount != len(manifest.Files)+1 {
		return errors.New("packet file count is not exact")
	}
	runnerRelative, err := relativeFromRoot(root, executable)
	if err != nil || runnerRelative != manifest.Runner {
		return errors.New("running executable is not the manifest-bound runner")
	}
	return verifyRegularFile(executable, expectedFiles[manifest.Runner])
}

func randomToken() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func createBuildRoot(parent string) (string, string, error) {
	if err := verifyExistingPathComponents(parent); err != nil {
		return "", "", err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() {
		return "", "", errors.New("build parent is not a plain directory")
	}
	for attempt := 0; attempt < 8; attempt++ {
		token, err := randomToken()
		if err != nil {
			return "", "", err
		}
		name := ".sos-msix-build-" + token
		root := filepath.Join(parent, name)
		if err := os.Mkdir(root, 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", "", err
		}
		marker, err := os.OpenFile(filepath.Join(root, buildMarkerName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", "", err
		}
		if _, err := marker.WriteString(buildMarkerContent); err != nil {
			marker.Close()
			return "", "", err
		}
		if err := marker.Close(); err != nil {
			return "", "", err
		}
		return root, name, nil
	}
	return "", "", errors.New("could not allocate a collision-free build root")
}

func copyBoundFile(source string, binding fileBinding, destinationRoot string, destinationRelative string) error {
	if err := verifyRegularFile(source, binding); err != nil {
		return err
	}
	parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(destinationRelative)))
	if _, err := ensureDirectory(destinationRoot, parent); err != nil {
		return err
	}
	destination := filepath.Join(destinationRoot, filepath.FromSlash(destinationRelative))
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := verifyRegularFile(destination, binding); err != nil {
		return err
	}
	return verifyRegularFile(source, binding)
}

func copySourceSnapshot(packetRoot string, buildRoot string, packet *packetManifest, source *sourceManifest) error {
	destination := filepath.Join(buildRoot, "source")
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	for _, file := range source.Files {
		from := filepath.Join(packetRoot, filepath.FromSlash(packet.SourceRoot), filepath.FromSlash(file.Path))
		if err := copyBoundFile(from, file, destination, file.Path); err != nil {
			return err
		}
		if err := verifyRegularFile(filepath.Join(destination, filepath.FromSlash(file.Path)), file); err != nil {
			return err
		}
	}
	var manifestBinding fileBinding
	for _, bound := range packet.Files {
		if bound.Path == packet.SourceManifest {
			manifestBinding = bound
			break
		}
	}
	return copyBoundFile(filepath.Join(packetRoot, filepath.FromSlash(packet.SourceManifest)), manifestBinding, buildRoot, "source-manifest.json")
}

func assemblePayload(packetRoot string, buildRoot string, manifest *packetManifest) error {
	payload := filepath.Join(buildRoot, "payload")
	if err := os.Mkdir(payload, 0o700); err != nil {
		return err
	}
	bindings := make(map[string]fileBinding, len(manifest.Files))
	for _, binding := range manifest.Files {
		bindings[binding.Path] = binding
	}
	runtimeArchive := filepath.Join(packetRoot, filepath.FromSlash(manifest.PythonRuntime))
	if err := verifyRegularFile(runtimeArchive, bindings[manifest.PythonRuntime]); err != nil {
		return err
	}
	if err := extractRuntimeArchive(runtimeArchive, filepath.Join(payload, "runtime")); err != nil {
		return err
	}
	if err := verifyRegularFile(runtimeArchive, bindings[manifest.PythonRuntime]); err != nil {
		return err
	}
	if err := copyBoundFile(filepath.Join(packetRoot, filepath.FromSlash(manifest.SOSLauncher)), bindings[manifest.SOSLauncher], payload, "sos.exe"); err != nil {
		return err
	}
	if err := copyBoundFile(filepath.Join(packetRoot, filepath.FromSlash(manifest.StoreEntrypoint)), bindings[manifest.StoreEntrypoint], payload, "sos-launcher.exe"); err != nil {
		return err
	}
	if err := copyBoundFile(filepath.Join(packetRoot, filepath.FromSlash(manifest.UV)), bindings[manifest.UV], payload, "bootstrap/uv.exe"); err != nil {
		return err
	}
	for _, wheel := range manifest.Wheelhouse {
		if err := copyBoundFile(filepath.Join(packetRoot, filepath.FromSlash(wheel)), bindings[wheel], payload, wheel); err != nil {
			return err
		}
	}
	marker, err := os.OpenFile(filepath.Join(payload, ".sos-msix-disposable-payload-v1"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := marker.WriteString("sos-windows-msix-disposable-payload-v1\n"); err != nil {
		marker.Close()
		return err
	}
	return marker.Close()
}

type boundedBuffer struct {
	data     []byte
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := maxProcessOutput - len(buffer.data)
	if remaining > 0 {
		count := len(value)
		if count > remaining {
			count = remaining
		}
		buffer.data = append(buffer.data, value[:count]...)
	}
	if len(value) > remaining {
		buffer.overflow = true
	}
	return len(value), nil
}

func closedEnvironment(buildRoot string) ([]string, error) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" || strings.ContainsAny(systemRoot, "\r\n") || !filepath.IsAbs(systemRoot) || filepath.Clean(systemRoot) != systemRoot {
		return nil, errors.New("SystemRoot is unavailable")
	}
	if err := verifyExistingPathComponents(systemRoot); err != nil {
		return nil, errors.New("SystemRoot contains an unsafe component")
	}
	processTemp := filepath.Join(buildRoot, "process-temp")
	if err := os.Mkdir(processTemp, 0o700); err != nil {
		return nil, err
	}
	return []string{
		"SystemRoot=" + systemRoot,
		"TEMP=" + processTemp,
		"TMP=" + processTemp,
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONNOUSERSITE=1",
		"PYTHONSAFEPATH=1",
		"PYTHONIOENCODING=utf-8",
	}, nil
}

func runPython(python string, workingDirectory string, environment []string, timeout time.Duration, arguments ...string) error {
	info, err := os.Lstat(python)
	if err != nil || !info.Mode().IsRegular() || !filepath.IsAbs(python) {
		return errors.New("tool-runtime Python is invalid")
	}
	reparse, err := isReparse(python, info)
	if err != nil || reparse {
		return errors.New("tool-runtime Python is a reparse object")
	}
	command := exec.Command(python, arguments...)
	command.Dir = workingDirectory
	command.Env = environment
	command.Stdin = strings.NewReader("")
	var stdout, stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	timedOut, err := runCommandInJob(command, timeout)
	if timedOut {
		return errors.New("bounded Python operation timed out")
	}
	if stdout.overflow || stderr.overflow {
		return errors.New("bounded Python operation exceeded its output limit")
	}
	if err != nil {
		diagnostic := sha256.Sum256(stderr.data)
		return fmt.Errorf("bounded Python operation failed (diagnostic sha256:%x)", diagnostic)
	}
	return nil
}

func installExactWheelhouse(packetRoot string, buildRoot string, environment []string, manifest *packetManifest, bindings map[string]fileBinding) error {
	uv := filepath.Join(packetRoot, filepath.FromSlash(manifest.UV))
	if err := verifyRegularFile(uv, bindings[manifest.UV]); err != nil {
		return errors.New("bound uv executable is invalid")
	}
	python := filepath.Join(buildRoot, "payload", "runtime", "python.exe")
	pythonInfo, err := os.Lstat(python)
	if err != nil || !pythonInfo.Mode().IsRegular() {
		return errors.New("payload Python is invalid")
	}
	arguments := []string{
		"--no-config", "--no-cache", "--offline", "--no-python-downloads",
		"pip", "install", "--python", python, "--no-index", "--reinstall", "--no-deps",
	}
	for _, relative := range manifest.Wheelhouse {
		wheel := filepath.Join(packetRoot, filepath.FromSlash(relative))
		if err := verifyRegularFile(wheel, bindings[relative]); err != nil {
			return errors.New("bound wheelhouse entry is invalid")
		}
		arguments = append(arguments, wheel)
	}
	command := exec.Command(uv, arguments...)
	command.Dir = buildRoot
	command.Env = environment
	command.Stdin = strings.NewReader("")
	var stdout, stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	timedOut, err := runCommandInJob(command, 10*time.Minute)
	if timedOut {
		return errors.New("bounded wheelhouse installation timed out")
	}
	if stdout.overflow || stderr.overflow {
		return errors.New("bounded wheelhouse installation exceeded its output limit")
	}
	if err != nil {
		diagnostic := sha256.Sum256(stderr.data)
		return fmt.Errorf("bounded wheelhouse installation failed (diagnostic sha256:%x)", diagnostic)
	}
	if err := verifyRegularFile(uv, bindings[manifest.UV]); err != nil {
		return err
	}
	return verifyInstalledSOSPackage(packetRoot, buildRoot, manifest)
}

func verifyInstalledSOSPackage(packetRoot string, buildRoot string, manifest *packetManifest) error {
	var wheelPath string
	for _, relative := range manifest.Wheelhouse {
		if strings.HasPrefix(filepath.Base(relative), "sigma_operator_stack-") {
			wheelPath = filepath.Join(packetRoot, filepath.FromSlash(relative))
			break
		}
	}
	if wheelPath == "" {
		return errors.New("SOS wheel is missing")
	}
	wheel, err := zip.OpenReader(wheelPath)
	if err != nil {
		return errors.New("SOS wheel cannot be opened")
	}
	defer wheel.Close()
	expected := make(map[string]fileBinding)
	for _, entry := range wheel.File {
		if entry.FileInfo().IsDir() || !strings.HasPrefix(entry.Name, "sos/") {
			continue
		}
		relative := strings.TrimPrefix(entry.Name, "sos/")
		if relative == "" || strings.Contains(relative, "\\") {
			return errors.New("SOS wheel package path is invalid")
		}
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
		if clean != relative || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("SOS wheel package path is unsafe")
		}
		input, err := entry.Open()
		if err != nil {
			return errors.New("SOS wheel package entry cannot be opened")
		}
		digest := sha256.New()
		size, copyErr := io.Copy(digest, input)
		closeErr := input.Close()
		if copyErr != nil || closeErr != nil || size != int64(entry.UncompressedSize64) {
			return errors.New("SOS wheel package entry cannot be read")
		}
		if _, duplicate := expected[relative]; duplicate {
			return errors.New("SOS wheel contains a duplicate package entry")
		}
		expected[relative] = fileBinding{Path: relative, SHA256: hex.EncodeToString(digest.Sum(nil)), Size: size}
	}
	if len(expected) == 0 {
		return errors.New("SOS wheel package is empty")
	}
	installedRoot := filepath.Join(buildRoot, "payload", "runtime", "Lib", "site-packages", "sos")
	observed := make([]string, 0, len(expected))
	err = filepath.Walk(installedRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(installedRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasSuffix(strings.ToLower(relative), ".pyc") || strings.Contains(relative, "/__pycache__/") {
			return nil
		}
		binding, ok := expected[relative]
		if !ok {
			return errors.New("installed SOS package contains an unbound file")
		}
		if err := verifyRegularFile(path, binding); err != nil {
			return errors.New("installed SOS package differs from the exact wheel")
		}
		observed = append(observed, relative)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(observed)
	expectedNames := make([]string, 0, len(expected))
	for name := range expected {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(expectedNames)
	if strings.Join(observed, "\n") != strings.Join(expectedNames, "\n") {
		return errors.New("installed SOS package inventory differs from the exact wheel")
	}
	return nil
}

func verifyMakeAppx(binding makeAppxBinding) (string, error) {
	programFiles, err := programFilesX86Path()
	if err != nil {
		return "", errors.New("Program Files x86 Known Folder is unavailable")
	}
	if err := requireLocalFixedNTFS(programFiles); err != nil {
		return "", errors.New("Program Files x86 is not on an admitted local fixed NTFS volume")
	}
	if err := verifyExistingPathComponents(programFiles); err != nil {
		return "", errors.New("ProgramFiles(x86) contains an unsafe component")
	}
	makeAppx := filepath.Join(programFiles, filepath.FromSlash(binding.ProgramFilesX86RelativePath))
	relative, err := filepath.Rel(programFiles, makeAppx)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("MakeAppx path escapes ProgramFiles(x86)")
	}
	if err := verifyExistingPathComponents(makeAppx); err != nil {
		return "", errors.New("MakeAppx path contains an unsafe component")
	}
	info, err := os.Lstat(makeAppx)
	if err != nil || !info.Mode().IsRegular() || info.Size() != binding.Size {
		return "", errors.New("MakeAppx is missing or does not match its bound size")
	}
	reparse, err := isReparse(makeAppx, info)
	if err != nil || reparse {
		return "", errors.New("MakeAppx is a link or reparse object")
	}
	digest, err := sha256File(makeAppx)
	if err != nil || digest != binding.SHA256 {
		return "", errors.New("MakeAppx digest does not match the packet binding")
	}
	return makeAppx, nil
}

func removeOwnedBuildRoot(root string) error {
	marker := filepath.Join(root, buildMarkerName)
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != buildMarkerContent {
		return errors.New("build ownership marker is invalid")
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		reparse, err := isReparse(path, info)
		if err != nil || reparse || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("build root contains a link or reparse object")
		}
		unexpectedStreams, err := hasUnexpectedStreams(path)
		if err != nil || unexpectedStreams {
			return errors.New("build root contains an alternate data stream")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(root)
}

func execute() *buildError {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return stop("SOS_MSIX_PLATFORM_UNSUPPORTED", "This build packet supports Windows 11 x86_64 only.", nil)
	}
	elevated, elevationErr := currentProcessElevated()
	uacEnabled, uacErr := userAccountControlEnabled()
	if elevationErr != nil || uacErr != nil {
		return stop("SOS_ALPHA_ELEVATION_STATE_UNAVAILABLE", "Windows elevation or UAC state could not be verified before packet observation.", nil)
	}
	if !uacEnabled {
		return stop("SOS_ALPHA_UAC_DISABLED_UNSUPPORTED", "Windows User Account Control is disabled; use a supported Windows host.", nil)
	}
	if elevated {
		return stop("SOS_ALPHA_ELEVATION_FORBIDDEN", "Run the MSIX builder from an ordinary non-Administrator Windows session.", nil)
	}
	if !hex40.MatchString(candidate) || !hex40.MatchString(tree) || !hex64.MatchString(inputLockDigest) {
		return stop("SOS_MSIX_RUNNER_AUTHORITY_UNBOUND", "The native build runner lacks exact candidate, tree, or input-lock bindings.", nil)
	}
	if len(os.Args) != 1 {
		return stop("SOS_MSIX_ARGUMENTS_INVALID", "Run Build-SOS-MSIX.exe without command-line arguments.", nil)
	}
	executable, err := os.Executable()
	if err != nil {
		return stop("SOS_MSIX_RUNNER_LOCATION_UNAVAILABLE", "The native build runner could not locate itself.", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return stop("SOS_MSIX_RUNNER_LOCATION_UNAVAILABLE", "The native build runner could not establish its absolute location.", err)
	}
	packetRoot := filepath.Dir(executable)
	if err := requireLocalFixedNTFS(packetRoot); err != nil {
		return stop("SOS_MSIX_PACKET_VOLUME_UNSUPPORTED", "The build packet must be on a local fixed NTFS volume, not a mapped, substituted, remote, or non-NTFS volume.", err)
	}
	if err := verifyExistingPathComponents(packetRoot); err != nil {
		return stop("SOS_MSIX_PACKET_ROOT_INVALID", "The packet root contains an unsafe path component.", err)
	}
	inputLock, inputLockBinding, err := loadInputLock(packetRoot, candidate, tree, inputLockDigest)
	if err != nil {
		return stop("SOS_MSIX_INPUT_LOCK_INVALID", "The candidate-owned input-lock is invalid or does not match the native runner.", err)
	}
	var packet packetManifest
	packetManifestBytes, err := decodeClosedJSON(filepath.Join(packetRoot, packetManifestName), &packet)
	if err != nil {
		return stop("SOS_MSIX_PACKET_MANIFEST_INVALID", "The closed packet manifest is invalid.", err)
	}
	packetManifestBinding := bindingForBytes(packetManifestName, packetManifestBytes)
	if err := validatePacketManifest(&packet); err != nil {
		return stop("SOS_MSIX_PACKET_MANIFEST_INVALID", "The closed packet manifest is invalid.", err)
	}
	if packet.Candidate != candidate || packet.Tree != tree {
		return stop("SOS_MSIX_RUNNER_AUTHORITY_MISMATCH", "The native runner and packet manifest authority bindings differ.", nil)
	}
	if err := validatePacketAgainstInputLock(&packet, inputLock, inputLockBinding); err != nil {
		return stop("SOS_MSIX_INPUT_LOCK_MISMATCH", "The packet artifacts differ from the candidate-owned input-lock.", err)
	}
	if err := verifyPacket(packetRoot, &packet, executable, packetManifestBinding); err != nil {
		return stop("SOS_MSIX_PACKET_INVENTORY_INVALID", "The packet inventory, object types, sizes, or digests are not exact.", err)
	}
	source, err := loadSourceManifest(packetRoot, &packet)
	if err != nil {
		return stop("SOS_MSIX_SOURCE_MANIFEST_INVALID", "The source snapshot binding is invalid.", err)
	}
	makeAppx, err := verifyMakeAppx(packet.MakeAppx)
	if err != nil {
		return stop("SOS_MSIX_MAKEAPPX_BINDING_INVALID", "The exact reviewed MakeAppx.exe is unavailable.", err)
	}
	buildRoot, buildID, err := createBuildRoot(filepath.Dir(packetRoot))
	if err != nil {
		return stop("SOS_MSIX_BUILD_ROOT_CREATE_FAILED", "A cryptographically named disposable build root could not be created.", err)
	}
	fail := func(code string, problem string, cause error) *buildError {
		failure := stop(code, problem, cause)
		failure.buildID = buildID
		return failure
	}
	if err := copySourceSnapshot(packetRoot, buildRoot, &packet, source); err != nil {
		return fail("SOS_MSIX_SOURCE_SNAPSHOT_COPY_FAILED", "The exact source snapshot could not be copied into the disposable build root.", err)
	}
	bindings := make(map[string]fileBinding, len(packet.Files))
	for _, binding := range packet.Files {
		bindings[binding.Path] = binding
	}
	runtimeArchive := filepath.Join(packetRoot, filepath.FromSlash(packet.PythonRuntime))
	if err := verifyRegularFile(runtimeArchive, bindings[packet.PythonRuntime]); err != nil {
		return fail("SOS_MSIX_TOOL_RUNTIME_BINDING_INVALID", "The exact Python tool runtime binding is invalid.", err)
	}
	if err := extractRuntimeArchive(runtimeArchive, filepath.Join(buildRoot, "tool-runtime")); err != nil {
		return fail("SOS_MSIX_TOOL_RUNTIME_EXTRACT_FAILED", "The exact Python tool runtime could not be safely extracted.", err)
	}
	if err := verifyRegularFile(runtimeArchive, bindings[packet.PythonRuntime]); err != nil {
		return fail("SOS_MSIX_TOOL_RUNTIME_DRIFTED", "The exact Python tool runtime changed during extraction.", err)
	}
	if err := assemblePayload(packetRoot, buildRoot, &packet); err != nil {
		return fail("SOS_MSIX_PAYLOAD_ASSEMBLY_FAILED", "The immutable MSIX payload could not be assembled.", err)
	}
	environment, err := closedEnvironment(buildRoot)
	if err != nil {
		return fail("SOS_MSIX_TOOL_ENVIRONMENT_INVALID", "The closed build-tool environment could not be created.", err)
	}
	if err := installExactWheelhouse(packetRoot, buildRoot, environment, &packet, bindings); err != nil {
		return fail("SOS_MSIX_WHEELHOUSE_INSTALL_FAILED", "The exact offline wheelhouse could not be installed into the immutable payload runtime.", err)
	}
	python := filepath.Join(buildRoot, "tool-runtime", "python.exe")
	sourceRoot := filepath.Join(buildRoot, "source")
	sourceManifestPath := filepath.Join(buildRoot, "source-manifest.json")
	payloadRoot := filepath.Join(buildRoot, "payload")
	prepareTool := filepath.Join(sourceRoot, "tools", "prepare_windows_msix_payload.py")
	pipelineTool := filepath.Join(sourceRoot, "tools", "build_windows_msix_pipeline.py")
	if err := runPython(python, buildRoot, environment, 10*time.Minute,
		"-I", "-B", prepareTool, "--payload-root", payloadRoot,
	); err != nil {
		return fail("SOS_MSIX_PAYLOAD_PREPARATION_FAILED", "The exact payload preparation step did not pass.", err)
	}
	outputRoot := filepath.Join(buildRoot, "pipeline-output")
	if err := runPython(python, buildRoot, environment, 45*time.Minute,
		"-I", "-B", pipelineTool,
		"--source-root", sourceRoot,
		"--source-manifest", sourceManifestPath,
		"--candidate", packet.Candidate,
		"--tree", packet.Tree,
		"--payload-root", payloadRoot,
		"--makeappx", makeAppx,
		"--makeappx-sha256", packet.MakeAppx.SHA256,
		"--output-root", outputRoot,
	); err != nil {
		return fail("SOS_MSIX_PIPELINE_FAILED", "The exact two-pack/two-unpack pipeline did not pass.", err)
	}
	sourceManifestBinding := bindings[packet.SourceManifest]
	expectation := pipelineOutputExpectation{
		Candidate:            packet.Candidate,
		Tree:                 packet.Tree,
		MakeAppXSHA256:       packet.MakeAppx.SHA256,
		SourceManifestSHA256: sourceManifestBinding.SHA256,
		SourceTreeDigest:     source.InventoryDigest[len("sha256:"):],
	}
	prePublicationInventory, err := inspectPipelineOutput(outputRoot, expectation)
	if err != nil {
		return fail("SOS_MSIX_PIPELINE_OUTPUT_INVALID", "The pipeline output inventory is invalid.", err)
	}
	if err := verifyPacket(packetRoot, &packet, executable, packetManifestBinding); err != nil {
		return fail("SOS_MSIX_PACKET_DRIFTED", "The build packet changed during execution.", err)
	}
	makeAppxDigest, err := sha256File(makeAppx)
	if err != nil || makeAppxDigest != packet.MakeAppx.SHA256 {
		return fail("SOS_MSIX_MAKEAPPX_DRIFTED", "MakeAppx.exe changed during execution.", err)
	}
	finalOutput := filepath.Join(packetRoot, "output")
	if _, err := os.Lstat(finalOutput); !errors.Is(err, os.ErrNotExist) {
		return fail("SOS_MSIX_OUTPUT_EXISTS", "The packet output directory already exists.", err)
	}
	if err := os.Rename(outputRoot, finalOutput); err != nil {
		return fail("SOS_MSIX_OUTPUT_PUBLICATION_FAILED", "The verified output could not be atomically published beside the packet.", err)
	}
	postPublicationInventory, verifyErr := inspectPipelineOutput(finalOutput, expectation)
	if verifyErr == nil && !sameFileBindings(prePublicationInventory, postPublicationInventory) {
		verifyErr = errors.New("published output bytes differ from the admitted pre-publication inventory")
	}
	if verifyErr != nil {
		if rollbackErr := os.Rename(finalOutput, outputRoot); rollbackErr != nil {
			return fail("SOS_MSIX_OUTPUT_PUBLICATION_INVALID", "The published output failed exact re-verification and could not be rolled back into the preserved build root.", verifyErr)
		}
		return fail("SOS_MSIX_OUTPUT_PUBLICATION_INVALID", "The published output failed exact re-verification and was rolled back into the preserved build root.", verifyErr)
	}
	if err := removeOwnedBuildRoot(buildRoot); err != nil {
		return fail("SOS_MSIX_BUILD_ROOT_CLEANUP_FAILED", "The verified package was produced, but the marker-owned build root could not be removed safely.", err)
	}
	fmt.Println("SOS MSIX build passed.")
	fmt.Println("Package: output/SigmaOperatorStack_1.0.4.0_x64.msix")
	return nil
}

func main() {
	failure := execute()
	if failure == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "SOS build stopped.")
	fmt.Fprintln(os.Stderr, "Code:", failure.code)
	fmt.Fprintln(os.Stderr, "Problem:", failure.problem)
	if failure.buildID != "" {
		fmt.Fprintln(os.Stderr, "Preserved build id:", failure.buildID)
	}
	os.Exit(2)
}
