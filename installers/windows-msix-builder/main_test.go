package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func boundFile(t *testing.T, root string, relative string, content []byte) fileBinding {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return fileBinding{Path: relative, SHA256: digest, Size: int64(len(content))}
}

func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	initial, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(initial))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func TestSafeRelativePathRejectsWindowsAmbiguity(t *testing.T) {
	invalid := []string{
		"", "/absolute", `back\\slash`, "../escape", "a/./b", "a//b",
		"a:stream", "trailing.", "trailing ", "CON", "CONIN$", "conout$.txt",
		"aux.txt", "snowman-\u2603",
	}
	for _, value := range invalid {
		if _, err := safeRelativePath(value); err == nil {
			t.Fatalf("unsafe path accepted: %q", value)
		}
	}
	if observed, err := safeRelativePath("source/tools/build_windows_msix.py"); err != nil || observed != "source/tools/build_windows_msix.py" {
		t.Fatalf("safe path rejected: %q %v", observed, err)
	}
}

func TestFirstStreamClassificationAcceptsOnlyExpectedDirectoryEOFOrDefaultData(t *testing.T) {
	for _, test := range []struct {
		name        string
		isDirectory bool
		streamName  string
		observedErr error
		unexpected  bool
		wantError   bool
	}{
		{name: "empty directory", isDirectory: true, observedErr: syscall.Errno(38)},
		{name: "regular default stream", streamName: "::$DATA"},
		{name: "regular named stream", streamName: ":secret:$DATA", unexpected: true},
		{name: "directory named stream", isDirectory: true, streamName: ":secret:$DATA", unexpected: true},
		{name: "regular EOF is ambiguous", observedErr: syscall.Errno(38), wantError: true},
		{name: "directory unexpected error fails closed", isDirectory: true, observedErr: syscall.Errno(5), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			unexpected, err := classifyFirstStream(test.isDirectory, test.streamName, test.observedErr)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", err, test.wantError)
			}
			if unexpected != test.unexpected {
				t.Fatalf("unexpected = %v, want %v", unexpected, test.unexpected)
			}
		})
	}
}

func TestWindowsStreamObservationAcceptsOrdinaryDirectoriesAndRejectsNamedStreams(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}
	root := t.TempDir()
	unexpected, err := hasUnexpectedStreams(root)
	if err != nil || unexpected {
		t.Fatalf("ordinary directory stream observation failed: unexpected=%v err=%v", unexpected, err)
	}
	regular := filepath.Join(root, "regular.txt")
	if err := os.WriteFile(regular, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unexpected, err = hasUnexpectedStreams(regular)
	if err != nil || unexpected {
		t.Fatalf("ordinary file stream observation failed: unexpected=%v err=%v", unexpected, err)
	}
	if err := os.WriteFile(regular+":named", []byte("forbidden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unexpected, err = hasUnexpectedStreams(regular)
	if err != nil || !unexpected {
		t.Fatalf("named stream was not rejected: unexpected=%v err=%v", unexpected, err)
	}
}

func TestInventoryRejectsNoncanonicalOrdering(t *testing.T) {
	files := []fileBinding{
		{Path: "z-last", SHA256: strings.Repeat("a", 64), Size: 1},
		{Path: "a-first", SHA256: strings.Repeat("b", 64), Size: 1},
	}
	if err := validateFileBindings(files, len(files), inventoryDigest(files)); err == nil {
		t.Fatal("noncanonically ordered file bindings were accepted")
	}
	if !strictlySortedStrings(expectedWheels) {
		t.Fatal("repository-owned wheelhouse order is not canonical")
	}
	if strictlySortedStrings([]string{"wheelhouse/b.whl", "wheelhouse/a.whl"}) {
		t.Fatal("noncanonically ordered wheelhouse was accepted")
	}
}

func TestInventoryRejectsCaseInsensitiveDirectoryCollision(t *testing.T) {
	files := []fileBinding{
		{Path: "source/Tools/one.py", SHA256: strings.Repeat("a", 64), Size: 1},
		{Path: "source/tools/two.py", SHA256: strings.Repeat("b", 64), Size: 1},
	}
	if err := validateFileBindings(files, len(files), inventoryDigest(files)); err == nil {
		t.Fatal("case-insensitive directory collision was accepted")
	}
}

func syntheticBinding(path string, marker string) fileBinding {
	return fileBinding{Path: path, SHA256: strings.Repeat(marker, 64), Size: 1}
}

func validSyntheticInputLock() inputLockManifest {
	wheels := make([]fileBinding, len(expectedWheels))
	for index, path := range expectedWheels {
		wheels[index] = syntheticBinding(path, "a")
	}
	return inputLockManifest{
		Candidate: strings.Repeat("b", 40),
		Contract:  "sos_windows_msix_input_lock_v1",
		Git:       toolchainBinding{SHA256: strings.Repeat("c", 64), Version: "git version 2.43.0"},
		Go:        toolchainBinding{SHA256: strings.Repeat("d", 64), Version: "go1.27.0"},
		MakeAppx: makeAppxBinding{
			ProgramFilesX86RelativePath: "Windows Kits/10/bin/10.0.28000.0/x64/MakeAppx.exe",
			SHA256:                      strings.Repeat("e", 64),
			Size:                        1,
		},
		PythonRuntime:   syntheticBinding(expectedRuntimeName, "f"),
		SOSLauncher:     syntheticBinding(expectedSOSName, "1"),
		StoreEntrypoint: syntheticBinding(expectedStoreEntrypointName, "5"),
		SourceManifest:  syntheticBinding(expectedSourceRecord, "2"),
		Tree:            strings.Repeat("3", 40),
		UV:              syntheticBinding(expectedUVName, "4"),
		Wheelhouse:      wheels,
	}
}

func TestInputLockDigestAndPacketCrossBindings(t *testing.T) {
	root := t.TempDir()
	lock := validSyntheticInputLock()
	data := canonicalJSON(t, lock)
	if err := os.WriteFile(filepath.Join(root, expectedInputLock), data, 0o600); err != nil {
		t.Fatal(err)
	}
	lockBinding := bindingForBytes(expectedInputLock, data)
	loaded, observedBinding, err := loadInputLock(root, lock.Candidate, lock.Tree, lockBinding.SHA256)
	if err != nil {
		t.Fatalf("exact input-lock rejected: %v", err)
	}
	if observedBinding != lockBinding {
		t.Fatal("input-lock byte binding changed")
	}
	files := []fileBinding{lockBinding, lock.PythonRuntime, lock.SOSLauncher, lock.StoreEntrypoint, lock.SourceManifest, lock.UV}
	files = append(files, lock.Wheelhouse...)
	packet := packetManifest{MakeAppx: lock.MakeAppx, Wheelhouse: append([]string(nil), expectedWheels...), Files: files}
	if err := validatePacketAgainstInputLock(&packet, loaded, lockBinding); err != nil {
		t.Fatalf("exact packet/input-lock cross-binding rejected: %v", err)
	}
	packet.Files[1].SHA256 = strings.Repeat("9", 64)
	if err := validatePacketAgainstInputLock(&packet, loaded, lockBinding); err == nil {
		t.Fatal("packet drift from candidate-owned input-lock was accepted")
	}
	if _, _, err := loadInputLock(root, lock.Candidate, lock.Tree, strings.Repeat("0", 64)); err == nil {
		t.Fatal("runner/input-lock digest mismatch was accepted")
	}
}

func TestInputLockRejectsUnsortedWheelhouse(t *testing.T) {
	lock := validSyntheticInputLock()
	lock.Wheelhouse[0], lock.Wheelhouse[1] = lock.Wheelhouse[1], lock.Wheelhouse[0]
	if err := validateInputLock(&lock, lock.Candidate, lock.Tree); err == nil {
		t.Fatal("unsorted input-lock wheelhouse was accepted")
	}
}

func TestDecodeClosedJSONRejectsUnknownDuplicateAndNoncanonical(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "manifest.json")
	valid := sourceManifest{
		Contract:        sourceContract,
		Candidate:       strings.Repeat("a", 40),
		Tree:            strings.Repeat("b", 40),
		FileCount:       1,
		InventoryDigest: "sha256:" + strings.Repeat("c", 64),
		Files:           []fileBinding{{Path: "README.md", SHA256: strings.Repeat("d", 64), Size: 1}},
	}
	if err := os.WriteFile(path, canonicalJSON(t, valid), 0o600); err != nil {
		t.Fatal(err)
	}
	var decoded sourceManifest
	if _, err := decodeClosedJSON(path, &decoded); err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	unknown := bytes.Replace(canonicalJSON(t, valid), []byte(`"tree":`), []byte(`"unknown":1,"tree":`), 1)
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeClosedJSON(path, &decoded); err == nil {
		t.Fatal("unknown key was accepted")
	}
	duplicate := bytes.Replace(canonicalJSON(t, valid), []byte(`"tree":`), []byte(`"tree":"`+strings.Repeat("b", 40)+`","tree":`), 1)
	if err := os.WriteFile(path, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeClosedJSON(path, &decoded); err == nil {
		t.Fatal("duplicate key was accepted")
	}
	noncanonical := append([]byte("  "), canonicalJSON(t, valid)...)
	if err := os.WriteFile(path, noncanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeClosedJSON(path, &decoded); err == nil {
		t.Fatal("noncanonical bytes were accepted")
	}
}

func TestClosedJSONRejectsNoncanonicalOrNegativeNumberGrammar(t *testing.T) {
	for _, value := range []string{"-0", "-1", "1.0", "1e0", "1E+0"} {
		payload := []byte(`{"count":` + value + `}`)
		if err := validateNoDuplicateJSONKeys(payload); err == nil {
			t.Fatalf("noncanonical JSON number accepted: %s", value)
		}
	}
	for _, value := range []string{"0", "1", "18446744073709551616"} {
		payload := []byte(`{"count":` + value + `}`)
		if err := validateNoDuplicateJSONKeys(payload); err != nil {
			t.Fatalf("canonical nonnegative integer rejected: %s: %v", value, err)
		}
	}
}

func writeRuntimeZip(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(output)
	for name, payload := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeArchiveExtractsExactRegularFiles(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "runtime.zip")
	writeRuntimeZip(t, archive, map[string][]byte{
		"python.exe":                        []byte("synthetic-python"),
		"Lib/site-packages/sos/__init__.py": []byte("synthetic-sos"),
	})
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := extractRuntimeArchive(archive, first); err != nil {
		t.Fatal(err)
	}
	if err := extractRuntimeArchive(archive, second); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"python.exe", "Lib/site-packages/sos/__init__.py"} {
		left, err := os.ReadFile(filepath.Join(first, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, filepath.FromSlash(relative)))
		if err != nil || !bytes.Equal(left, right) {
			t.Fatalf("independent extraction differs for %s", relative)
		}
	}
}

func TestRuntimeArchiveRejectsTraversalAndCaseCollision(t *testing.T) {
	for name, entries := range map[string]map[string][]byte{
		"traversal": {"../escape": []byte("x")},
		"collision": {"Lib/module.py": []byte("x"), "lib/other.py": []byte("y")},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "runtime.zip")
			writeRuntimeZip(t, archive, entries)
			if err := extractRuntimeArchive(archive, filepath.Join(root, "output")); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestPacketInventoryRequiresRunnerAndRejectsExtraFile(t *testing.T) {
	root := t.TempDir()
	runner := boundFile(t, root, expectedRunnerName, []byte("synthetic-runner"))
	sourceRecord := boundFile(t, root, expectedSourceRecord, []byte("{}\n"))
	files := []fileBinding{runner, sourceRecord}
	packet := packetManifest{Runner: expectedRunnerName, Files: files}
	if err := os.WriteFile(filepath.Join(root, packetManifestName), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestBinding := bindingForBytes(packetManifestName, []byte("{}\n"))
	if err := verifyPacket(root, &packet, filepath.Join(root, expectedRunnerName), manifestBinding); err != nil {
		t.Fatalf("exact packet rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.bin"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPacket(root, &packet, filepath.Join(root, expectedRunnerName), manifestBinding); err == nil {
		t.Fatal("unlisted packet file was accepted")
	}
}

func writeSyntheticPipelineOutput(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for name := range pipelineOutputNames {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic-output\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPipelineOutputInventoryBindsBytesAcrossPublication(t *testing.T) {
	root := filepath.Join(t.TempDir(), "output")
	writeSyntheticPipelineOutput(t, root)
	before, err := pipelineOutputInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, outputMSIXName)
	if err := os.WriteFile(target, []byte("synthetic-outpuT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := pipelineOutputInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	if sameFileBindings(before, after) {
		t.Fatal("same-size output byte substitution was not detected")
	}
}

func TestPipelineOutputInventoryRejectsAdditionalObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "output")
	writeSyntheticPipelineOutput(t, root)
	if err := os.WriteFile(filepath.Join(root, "unbound.txt"), []byte("extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pipelineOutputInventory(root); err == nil {
		t.Fatal("additional output artifact was accepted")
	}
}

func TestExactClosedReceiptRejectsMissingFalseBoolean(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "comparison.json")
	record := map[string]any{
		"byte_identical": false, "candidate": strings.Repeat("a", 40),
		"container_equivalence_claimed": false, "contract": outputComparisonContract,
		"first_msix_sha256":      "sha256:" + strings.Repeat("b", 64),
		"makeappx_sha256":        "sha256:" + strings.Repeat("c", 64),
		"package_content_digest": "sha256:" + strings.Repeat("d", 64),
		"package_file_count":     1, "payload_file_count": 1, "pyc_file_count": 0,
		"second_msix_sha256": "sha256:" + strings.Repeat("e", 64),
		"status":             "passed", "tree": strings.Repeat("f", 40),
		"verification_method": outputComparisonMethod,
	}
	if err := os.WriteFile(path, canonicalJSON(t, record), 0o600); err != nil {
		t.Fatal(err)
	}
	var decoded comparisonReceipt
	if err := decodeExactClosedJSON(path, &decoded, comparisonReceiptKeys); err == nil {
		t.Fatal("receipt missing an expected-false boolean was accepted")
	}
}

func TestRunnerSourceHasNoShellNetworkOrExternalDiscoveryTools(t *testing.T) {
	for _, name := range []string{
		"main.go", "manifest.go", "archive.go", "output.go",
		"platform_windows.go", "job_windows.go",
	} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(data))
		for _, forbidden := range []string{
			`"net/`, "powershell", "cmd.exe", "certutil", "git.exe", "tar.exe", "lookpath(",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden dependency %q", name, forbidden)
			}
		}
	}
}

func TestWindowsPlatformSourceUsesKnownFolderFixedNTFSAndJobObject(t *testing.T) {
	platform, err := os.ReadFile("platform_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	platformText := string(platform)
	for _, required := range []string{
		"SHGetKnownFolderPath", "folderIDProgramFilesX86", "GetVolumePathNameW", "GetDriveTypeW",
		"QueryDosDeviceW", "GetVolumeInformationW", "HarddiskVolume", "NTFS",
	} {
		if !strings.Contains(platformText, required) {
			t.Fatalf("Windows platform admission lacks %q", required)
		}
	}
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mainSource), `os.Getenv("ProgramFiles(x86)")`) {
		t.Fatal("MakeAppx authority still trusts ProgramFiles(x86) from the environment")
	}
	job, err := os.ReadFile("job_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	jobText := string(job)
	for _, required := range []string{
		"CreateJobObjectW", "SetInformationJobObject", "AssignProcessToJobObject",
		"jobObjectLimitKillOnJobClose", "CloseHandle",
	} {
		if !strings.Contains(jobText, required) {
			t.Fatalf("Windows process containment lacks %q", required)
		}
	}
}

func TestJobHelperProcess(t *testing.T) {
	if os.Getenv("SOS_MSIX_JOB_TEST_HELPER") != "1" {
		return
	}
	time.Sleep(5 * time.Second)
}

func TestNonWindowsJobStubKillsTimedOutProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the native Windows job implementation requires a Windows execution host")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestJobHelperProcess$")
	command.Env = append(os.Environ(), "SOS_MSIX_JOB_TEST_HELPER=1")
	timedOut, err := runCommandInJob(command, 25*time.Millisecond)
	if !timedOut || err == nil {
		t.Fatalf("timeout was not fail-closed: timed_out=%v err=%v", timedOut, err)
	}
}
