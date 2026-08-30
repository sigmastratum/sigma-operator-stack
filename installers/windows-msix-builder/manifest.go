package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	packetContract       = "sos_windows_msix_build_packet_v1"
	sourceContract       = "sos_windows_msix_source_manifest_v1"
	packetManifestName   = "packet-manifest.json"
	maxManifestBytes     = 8 * 1024 * 1024
	expectedRunnerName   = "Build-SOS-MSIX.exe"
	expectedSourceRoot   = "source"
	expectedSourceRecord = "source-manifest.json"
	expectedInputLock    = "input-lock.json"
	expectedRuntimeName  = "windows-python-runtime-3.12.14.zip"
	expectedSOSName      = "sos.exe"
	expectedUVName       = "uv.exe"
)

var (
	hex40                  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64                  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nonnegativeJSONInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	toolVersion            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,127}$`)
	expectedWheels         = []string{
		"wheelhouse/attrs-26.1.0-py3-none-any.whl",
		"wheelhouse/jsonschema-4.26.0-py3-none-any.whl",
		"wheelhouse/jsonschema_specifications-2025.9.1-py3-none-any.whl",
		"wheelhouse/referencing-0.37.0-py3-none-any.whl",
		"wheelhouse/rpds_py-2026.6.3-cp312-cp312-win_amd64.whl",
		"wheelhouse/sigma_operator_stack-0.1.0a2-py3-none-any.whl",
		"wheelhouse/typing_extensions-4.16.0-py3-none-any.whl",
	}
	windowsReservedNames = func() map[string]bool {
		result := map[string]bool{
			"CON": true, "CONIN$": true, "CONOUT$": true,
			"PRN": true, "AUX": true, "NUL": true,
		}
		for number := 1; number <= 9; number++ {
			result[fmt.Sprintf("COM%d", number)] = true
			result[fmt.Sprintf("LPT%d", number)] = true
		}
		return result
	}()
)

type fileBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type makeAppxBinding struct {
	ProgramFilesX86RelativePath string `json:"program_files_x86_relative_path"`
	SHA256                      string `json:"sha256"`
	Size                        int64  `json:"size"`
}

type toolchainBinding struct {
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

type inputLockManifest struct {
	Candidate      string           `json:"candidate"`
	Contract       string           `json:"contract"`
	Git            toolchainBinding `json:"git"`
	Go             toolchainBinding `json:"go"`
	MakeAppx       makeAppxBinding  `json:"makeappx"`
	PythonRuntime  fileBinding      `json:"python_runtime"`
	SOSLauncher    fileBinding      `json:"sos_launcher"`
	SourceManifest fileBinding      `json:"source_manifest"`
	Tree           string           `json:"tree"`
	UV             fileBinding      `json:"uv"`
	Wheelhouse     []fileBinding    `json:"wheelhouse"`
}

type packetManifest struct {
	Contract        string          `json:"contract"`
	Candidate       string          `json:"candidate"`
	Tree            string          `json:"tree"`
	Runner          string          `json:"runner"`
	SourceRoot      string          `json:"source_root"`
	SourceManifest  string          `json:"source_manifest"`
	InputLock       string          `json:"input_lock"`
	PythonRuntime   string          `json:"python_runtime"`
	SOSLauncher     string          `json:"sos_launcher"`
	UV              string          `json:"uv"`
	Wheelhouse      []string        `json:"wheelhouse"`
	MakeAppx        makeAppxBinding `json:"makeappx"`
	FileCount       int             `json:"file_count"`
	InventoryDigest string          `json:"inventory_digest"`
	Files           []fileBinding   `json:"files"`
}

type sourceManifest struct {
	Contract        string        `json:"contract"`
	Candidate       string        `json:"candidate"`
	Tree            string        `json:"tree"`
	FileCount       int           `json:"file_count"`
	InventoryDigest string        `json:"inventory_digest"`
	Files           []fileBinding `json:"files"`
}

func safeRelativePath(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return "", errors.New("path is not a forward-slash relative path")
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e || strings.ContainsRune(`<>:"|?*`, character) {
			return "", errors.New("path contains a Windows-unsafe character")
		}
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", errors.New("path contains an unsafe component")
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if windowsReservedNames[stem] {
			return "", errors.New("path contains a reserved Windows component")
		}
	}
	return strings.Join(parts, "/"), nil
}

func inventoryDigest(files []fileBinding) string {
	ordered := append([]fileBinding(nil), files...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Path < ordered[right].Path })
	digest := sha256.New()
	for _, file := range ordered {
		_, _ = io.WriteString(digest, file.Path)
		_, _ = digest.Write([]byte{0})
		_, _ = io.WriteString(digest, strconv.FormatInt(file.Size, 10))
		_, _ = digest.Write([]byte{0})
		_, _ = io.WriteString(digest, file.SHA256)
		_, _ = digest.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func validateFileBindings(files []fileBinding, expectedCount int, expectedDigest string) error {
	if expectedCount <= 0 || len(files) != expectedCount {
		return errors.New("file count binding is invalid")
	}
	type objectBinding struct {
		path      string
		directory bool
	}
	seen := make(map[string]objectBinding, len(files)*2)
	previousPath := ""
	for index, file := range files {
		path, err := safeRelativePath(file.Path)
		if err != nil || path != file.Path || file.Size < 0 || file.Size > maxPacketSingleFile || !hex64.MatchString(file.SHA256) {
			return errors.New("file binding is invalid")
		}
		if index > 0 && path <= previousPath {
			return errors.New("file bindings are not strictly ordered by path")
		}
		previousPath = path
		parts := strings.Split(path, "/")
		for index := 1; index <= len(parts); index++ {
			objectPath := strings.Join(parts[:index], "/")
			directory := index < len(parts)
			folded := strings.ToLower(objectPath)
			if previous, ok := seen[folded]; ok {
				if previous.path != objectPath || previous.directory != directory {
					return fmt.Errorf("case-insensitive object collision between %q and %q", previous.path, objectPath)
				}
				if !directory {
					return fmt.Errorf("duplicate file binding for %q", objectPath)
				}
				continue
			}
			seen[folded] = objectBinding{path: objectPath, directory: directory}
		}
	}
	if inventoryDigest(files) != expectedDigest {
		return errors.New("inventory digest binding is invalid")
	}
	return nil
}

func validateNoDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bufio.NewReader(strings.NewReader(string(data))))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains more than one top-level value")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		if number, isNumber := token.(json.Number); isNumber && !nonnegativeJSONInteger.MatchString(number.String()) {
			return errors.New("JSON number is not a canonical nonnegative integer")
		}
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("JSON contains a duplicate or invalid object key")
			}
			seen[key] = true
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("JSON contains an unexpected delimiter")
	}
	return nil
}

func decodeClosedJSON(path string, destination any) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("manifest is not a regular file")
	}
	reparse, err := isReparse(path, info)
	if err != nil || reparse || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, errors.New("manifest object is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := validateNoDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	var generic any
	canonicalDecoder := json.NewDecoder(bytes.NewReader(data))
	canonicalDecoder.UseNumber()
	if err := canonicalDecoder.Decode(&generic); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return nil, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("manifest JSON is not canonical compact sorted-key JSON with one LF")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("manifest has trailing JSON data")
	}
	return data, nil
}

func validatePacketManifest(manifest *packetManifest) error {
	if manifest.Contract != packetContract || !hex40.MatchString(manifest.Candidate) || !hex40.MatchString(manifest.Tree) {
		return errors.New("packet authority binding is invalid")
	}
	if manifest.Runner != expectedRunnerName || manifest.SourceRoot != expectedSourceRoot ||
		manifest.SourceManifest != expectedSourceRecord || manifest.InputLock != expectedInputLock || manifest.PythonRuntime != expectedRuntimeName ||
		manifest.SOSLauncher != expectedSOSName || manifest.UV != expectedUVName {
		return errors.New("packet artifact naming contract is invalid")
	}
	if len(manifest.Wheelhouse) != len(expectedWheels) || !strictlySortedStrings(manifest.Wheelhouse) {
		return errors.New("wheelhouse inventory is invalid")
	}
	for index := range expectedWheels {
		if manifest.Wheelhouse[index] != expectedWheels[index] {
			return errors.New("wheelhouse inventory is invalid")
		}
	}
	makeAppxPath, err := safeRelativePath(manifest.MakeAppx.ProgramFilesX86RelativePath)
	if err != nil || makeAppxPath != manifest.MakeAppx.ProgramFilesX86RelativePath ||
		!strings.HasSuffix(strings.ToLower(makeAppxPath), "/makeappx.exe") ||
		!hex64.MatchString(manifest.MakeAppx.SHA256) || manifest.MakeAppx.Size <= 0 {
		return errors.New("MakeAppx binding is invalid")
	}
	if err := validateFileBindings(manifest.Files, manifest.FileCount, manifest.InventoryDigest); err != nil {
		return err
	}
	byPath := make(map[string]fileBinding, len(manifest.Files))
	for _, file := range manifest.Files {
		byPath[file.Path] = file
	}
	for _, required := range append([]string{
		manifest.Runner, manifest.SourceManifest, manifest.InputLock, manifest.PythonRuntime, manifest.SOSLauncher, manifest.UV,
	}, manifest.Wheelhouse...) {
		if _, ok := byPath[required]; !ok {
			return errors.New("packet required artifact is not inventory-bound")
		}
	}
	if _, included := byPath[packetManifestName]; included {
		return errors.New("packet manifest cannot recursively bind itself")
	}
	for _, file := range manifest.Files {
		if strings.EqualFold(file.Path, packetManifestName) {
			return errors.New("packet inventory collides with the implicit packet manifest")
		}
	}
	return nil
}

func validateLockedFile(binding fileBinding, expectedPath string) error {
	if binding.Path != expectedPath || binding.Size <= 0 || binding.Size > maxPacketSingleFile || !hex64.MatchString(binding.SHA256) {
		return errors.New("input-lock file binding is invalid")
	}
	path, err := safeRelativePath(binding.Path)
	if err != nil || path != binding.Path {
		return errors.New("input-lock file path is invalid")
	}
	return nil
}

func validateInputLock(lock *inputLockManifest, expectedCandidate string, expectedTree string) error {
	if lock.Contract != "sos_windows_msix_input_lock_v1" || lock.Candidate != expectedCandidate || lock.Tree != expectedTree {
		return errors.New("input-lock authority binding is invalid")
	}
	if !hex64.MatchString(lock.Git.SHA256) || !toolVersion.MatchString(lock.Git.Version) ||
		!strings.HasPrefix(lock.Git.Version, "git version ") ||
		!hex64.MatchString(lock.Go.SHA256) || lock.Go.Version != "go1.27.0" {
		return errors.New("input-lock toolchain binding is invalid")
	}
	makeAppxPath, err := safeRelativePath(lock.MakeAppx.ProgramFilesX86RelativePath)
	if err != nil || makeAppxPath != lock.MakeAppx.ProgramFilesX86RelativePath ||
		!strings.HasSuffix(strings.ToLower(makeAppxPath), "/makeappx.exe") ||
		lock.MakeAppx.Size <= 0 || !hex64.MatchString(lock.MakeAppx.SHA256) {
		return errors.New("input-lock MakeAppx binding is invalid")
	}
	for binding, expectedPath := range map[fileBinding]string{
		lock.PythonRuntime:  expectedRuntimeName,
		lock.SOSLauncher:    expectedSOSName,
		lock.SourceManifest: expectedSourceRecord,
		lock.UV:             expectedUVName,
	} {
		if err := validateLockedFile(binding, expectedPath); err != nil {
			return err
		}
	}
	if len(lock.Wheelhouse) != len(expectedWheels) {
		return errors.New("input-lock wheelhouse is invalid")
	}
	for index, binding := range lock.Wheelhouse {
		if index > 0 && binding.Path <= lock.Wheelhouse[index-1].Path {
			return errors.New("input-lock wheelhouse is not strictly ordered")
		}
		if err := validateLockedFile(binding, expectedWheels[index]); err != nil {
			return err
		}
	}
	return nil
}

func loadInputLock(packetRoot string, expectedCandidate string, expectedTree string, expectedDigest string) (*inputLockManifest, fileBinding, error) {
	path := filepath.Join(packetRoot, expectedInputLock)
	var lock inputLockManifest
	data, err := decodeClosedJSON(path, &lock)
	if err != nil {
		return nil, fileBinding{}, err
	}
	unexpectedStreams, err := hasUnexpectedStreams(path)
	if err != nil || unexpectedStreams {
		return nil, fileBinding{}, errors.New("input-lock contains an alternate data stream")
	}
	binding := bindingForBytes(expectedInputLock, data)
	if binding.SHA256 != expectedDigest {
		return nil, fileBinding{}, errors.New("input-lock digest does not match the runner authority")
	}
	if err := validateInputLock(&lock, expectedCandidate, expectedTree); err != nil {
		return nil, fileBinding{}, err
	}
	return &lock, binding, nil
}

func validatePacketAgainstInputLock(packet *packetManifest, lock *inputLockManifest, lockBinding fileBinding) error {
	if len(packet.Wheelhouse) != len(expectedWheels) || len(lock.Wheelhouse) != len(expectedWheels) {
		return errors.New("packet or input-lock wheelhouse length is invalid")
	}
	if packet.MakeAppx != lock.MakeAppx {
		return errors.New("packet MakeAppx binding differs from the input-lock")
	}
	packetFiles := make(map[string]fileBinding, len(packet.Files))
	for _, binding := range packet.Files {
		packetFiles[binding.Path] = binding
	}
	if packetFiles[expectedInputLock] != lockBinding ||
		packetFiles[expectedRuntimeName] != lock.PythonRuntime ||
		packetFiles[expectedSOSName] != lock.SOSLauncher ||
		packetFiles[expectedSourceRecord] != lock.SourceManifest ||
		packetFiles[expectedUVName] != lock.UV {
		return errors.New("packet artifacts differ from the input-lock")
	}
	for index, expectedPath := range expectedWheels {
		if packet.Wheelhouse[index] != expectedPath || packetFiles[expectedPath] != lock.Wheelhouse[index] {
			return errors.New("packet wheelhouse differs from the input-lock")
		}
	}
	return nil
}

func strictlySortedStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] <= values[index-1] {
			return false
		}
	}
	return true
}

func loadSourceManifest(packetRoot string, packet *packetManifest) (*sourceManifest, error) {
	path := filepath.Join(packetRoot, filepath.FromSlash(packet.SourceManifest))
	var source sourceManifest
	if _, err := decodeClosedJSON(path, &source); err != nil {
		return nil, err
	}
	if source.Contract != sourceContract || source.Candidate != packet.Candidate || source.Tree != packet.Tree {
		return nil, errors.New("source authority binding is invalid")
	}
	if err := validateFileBindings(source.Files, source.FileCount, source.InventoryDigest); err != nil {
		return nil, err
	}
	prefix := packet.SourceRoot + "/"
	packetSource := map[string]fileBinding{}
	for _, file := range packet.Files {
		if strings.HasPrefix(file.Path, prefix) {
			stripped := file
			stripped.Path = strings.TrimPrefix(file.Path, prefix)
			packetSource[stripped.Path] = stripped
		}
	}
	if len(packetSource) != len(source.Files) {
		return nil, errors.New("source packet inventory is incomplete")
	}
	for _, file := range source.Files {
		bound, ok := packetSource[file.Path]
		if !ok || bound.Size != file.Size || bound.SHA256 != file.SHA256 {
			return nil, errors.New("source packet inventory does not match source manifest")
		}
		if strings.EqualFold(file.Path, ".git") || strings.HasPrefix(strings.ToLower(file.Path), ".git/") {
			return nil, errors.New("Git metadata is forbidden in the source snapshot")
		}
	}
	return &source, nil
}
