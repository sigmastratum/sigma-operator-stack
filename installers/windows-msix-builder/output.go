package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	outputMSIXName                = "SigmaOperatorStack_1.0.4.0_x64.msix"
	outputBuildResultName         = "build-result.json"
	outputFirstBuildName          = "first-build.json"
	outputFirstContentSafetyName  = "first-content-safety.json"
	outputComparisonName          = "msix-comparison.json"
	outputSecondBuildName         = "second-build.json"
	outputSecondContentSafetyName = "second-content-safety.json"
	outputPackageIdentityName     = "SSRG.SigmaOperatorStack"
	outputPackageFamilyName       = "SSRG.SigmaOperatorStack_2358e20nvr064"
	outputStoreID                 = "9NNZT70C613H"
	outputVersion                 = "1.0.4.0"
	outputBuilderContract         = "sos_windows_unsigned_msix_build_v1"
	outputComparisonContract      = "sos_windows_msix_semantic_comparison_v2"
	outputContentSafetyContract   = "sos_windows_msix_content_safety_v1"
	outputBuildResultContract     = "sos_windows_store_msix_build_result_v2"
	outputComparisonMethod        = "default_makeappx_unpack_exact_content_v1"
	outputBuildResultVerification = "two_pack_two_default_unpack_exact_content_v1"
)

var pipelineOutputNames = map[string]bool{
	outputMSIXName:                true,
	outputBuildResultName:         true,
	outputFirstBuildName:          true,
	outputFirstContentSafetyName:  true,
	outputComparisonName:          true,
	outputSecondBuildName:         true,
	outputSecondContentSafetyName: true,
}

var (
	builderReceiptKeys = map[string]bool{
		"candidate": true, "contract": true, "makeappx_sha256": true, "msix_sha256": true,
		"msix_version": true, "package_family_name": true, "package_identity_name": true,
		"payload_file_count": true, "payload_tree_digest": true, "source_manifest_sha256": true,
		"source_tree_digest": true, "stage_file_count": true, "stage_tree_digest": true,
		"status": true, "store_id": true, "tree": true,
	}
	comparisonReceiptKeys = map[string]bool{
		"byte_identical": true, "candidate": true, "container_equivalence_claimed": true,
		"contract": true, "first_msix_sha256": true, "makeappx_sha256": true,
		"package_content_digest": true, "package_file_count": true, "payload_file_count": true,
		"pyc_file_count": true, "raw_content_serialized": true, "second_msix_sha256": true,
		"status": true, "tree": true, "verification_method": true,
	}
	contentSafetyReceiptKeys = map[string]bool{
		"absolute_paths_serialized": true, "candidate": true, "contract": true,
		"opaque_bound_file_count": true, "package_content_digest": true, "package_file_count": true,
		"payload_file_count": true, "raw_content_serialized": true, "report_digest": true,
		"scanned_text_file_count": true, "status": true, "tree": true,
	}
	buildResultReceiptKeys = map[string]bool{
		"candidate": true, "comparison_receipt_sha256": true, "contract": true,
		"first_build_receipt_sha256": true, "first_content_safety_receipt_sha256": true,
		"makeappx_sha256": true, "msix_sha256": true, "network_phase": true,
		"package_content_digest": true, "package_identity_name": true,
		"second_build_receipt_sha256": true, "second_content_safety_receipt_sha256": true,
		"source_manifest_sha256": true, "source_tree_digest": true, "status": true,
		"store_id": true, "tree": true, "verification_method": true,
	}
)

type pipelineOutputExpectation struct {
	Candidate            string
	Tree                 string
	MakeAppXSHA256       string
	SourceManifestSHA256 string
	SourceTreeDigest     string
}

type builderReceipt struct {
	Candidate            string `json:"candidate"`
	Contract             string `json:"contract"`
	MakeAppXSHA256       string `json:"makeappx_sha256"`
	MSIXSHA256           string `json:"msix_sha256"`
	MSIXVersion          string `json:"msix_version"`
	PackageFamilyName    string `json:"package_family_name"`
	PackageIdentityName  string `json:"package_identity_name"`
	PayloadFileCount     int    `json:"payload_file_count"`
	PayloadTreeDigest    string `json:"payload_tree_digest"`
	SourceManifestSHA256 string `json:"source_manifest_sha256"`
	SourceTreeDigest     string `json:"source_tree_digest"`
	StageFileCount       int    `json:"stage_file_count"`
	StageTreeDigest      string `json:"stage_tree_digest"`
	Status               string `json:"status"`
	StoreID              string `json:"store_id"`
	Tree                 string `json:"tree"`
}

type comparisonReceipt struct {
	ByteIdentical               bool   `json:"byte_identical"`
	Candidate                   string `json:"candidate"`
	ContainerEquivalenceClaimed bool   `json:"container_equivalence_claimed"`
	Contract                    string `json:"contract"`
	FirstMSIXSHA256             string `json:"first_msix_sha256"`
	MakeAppXSHA256              string `json:"makeappx_sha256"`
	PackageContentDigest        string `json:"package_content_digest"`
	PackageFileCount            int    `json:"package_file_count"`
	PayloadFileCount            int    `json:"payload_file_count"`
	PYCFileCount                int    `json:"pyc_file_count"`
	RawContentSerialized        bool   `json:"raw_content_serialized"`
	SecondMSIXSHA256            string `json:"second_msix_sha256"`
	Status                      string `json:"status"`
	Tree                        string `json:"tree"`
	VerificationMethod          string `json:"verification_method"`
}

type contentSafetyReceipt struct {
	AbsolutePathsSerialized bool   `json:"absolute_paths_serialized"`
	Candidate               string `json:"candidate"`
	Contract                string `json:"contract"`
	OpaqueBoundFileCount    int    `json:"opaque_bound_file_count"`
	PackageContentDigest    string `json:"package_content_digest"`
	PackageFileCount        int    `json:"package_file_count"`
	PayloadFileCount        int    `json:"payload_file_count"`
	RawContentSerialized    bool   `json:"raw_content_serialized"`
	ReportDigest            string `json:"report_digest"`
	ScannedTextFileCount    int    `json:"scanned_text_file_count"`
	Status                  string `json:"status"`
	Tree                    string `json:"tree"`
}

type buildResultReceipt struct {
	Candidate                        string `json:"candidate"`
	ComparisonReceiptSHA256          string `json:"comparison_receipt_sha256"`
	Contract                         string `json:"contract"`
	FirstBuildReceiptSHA256          string `json:"first_build_receipt_sha256"`
	FirstContentSafetyReceiptSHA256  string `json:"first_content_safety_receipt_sha256"`
	MakeAppXSHA256                   string `json:"makeappx_sha256"`
	MSIXSHA256                       string `json:"msix_sha256"`
	NetworkPhase                     string `json:"network_phase"`
	PackageContentDigest             string `json:"package_content_digest"`
	PackageIdentityName              string `json:"package_identity_name"`
	SecondBuildReceiptSHA256         string `json:"second_build_receipt_sha256"`
	SecondContentSafetyReceiptSHA256 string `json:"second_content_safety_receipt_sha256"`
	SourceManifestSHA256             string `json:"source_manifest_sha256"`
	SourceTreeDigest                 string `json:"source_tree_digest"`
	Status                           string `json:"status"`
	StoreID                          string `json:"store_id"`
	Tree                             string `json:"tree"`
	VerificationMethod               string `json:"verification_method"`
}

func pipelineOutputInventory(root string) ([]fileBinding, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("pipeline output root is not a plain directory")
	}
	reparse, err := isReparse(root, rootInfo)
	if err != nil || reparse {
		return nil, errors.New("pipeline output root is a reparse object")
	}
	unexpectedStreams, err := hasUnexpectedStreams(root)
	if err != nil || unexpectedStreams {
		return nil, errors.New("pipeline output root contains an alternate data stream")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(pipelineOutputNames) {
		return nil, errors.New("pipeline output inventory is not exact")
	}
	inventory := make([]fileBinding, 0, len(entries))
	for _, entry := range entries {
		if !pipelineOutputNames[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("pipeline output contains an unexpected object")
		}
		path := filepath.Join(root, entry.Name())
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 {
			return nil, errors.New("pipeline output artifact is invalid")
		}
		reparse, err := isReparse(path, before)
		if err != nil || reparse {
			return nil, errors.New("pipeline output artifact is a reparse object")
		}
		unexpectedStreams, err := hasUnexpectedStreams(path)
		if err != nil || unexpectedStreams {
			return nil, errors.New("pipeline output artifact contains an alternate data stream")
		}
		digest, err := sha256File(path)
		if err != nil {
			return nil, errors.New("pipeline output artifact could not be hashed")
		}
		after, err := os.Lstat(path)
		if err != nil || !after.Mode().IsRegular() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return nil, errors.New("pipeline output artifact changed while it was inventoried")
		}
		reparse, err = isReparse(path, after)
		if err != nil || reparse {
			return nil, errors.New("pipeline output artifact changed into a reparse object")
		}
		unexpectedStreams, err = hasUnexpectedStreams(path)
		if err != nil || unexpectedStreams {
			return nil, errors.New("pipeline output artifact gained an alternate data stream")
		}
		inventory = append(inventory, fileBinding{Path: entry.Name(), SHA256: digest, Size: before.Size()})
	}
	sort.Slice(inventory, func(left, right int) bool { return inventory[left].Path < inventory[right].Path })
	return inventory, nil
}

func sameFileBindings(left []fileBinding, right []fileBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func outputBindingsByPath(inventory []fileBinding) map[string]fileBinding {
	result := make(map[string]fileBinding, len(inventory))
	for _, binding := range inventory {
		result[binding.Path] = binding
	}
	return result
}

func prefixedDigest(binding fileBinding) string {
	return "sha256:" + binding.SHA256
}

func validPrefixedDigest(value string) bool {
	return len(value) == len("sha256:")+64 && value[:len("sha256:")] == "sha256:" && hex64.MatchString(value[len("sha256:"):])
}

func decodeExactClosedJSON(path string, destination any, expectedKeys map[string]bool) error {
	data, err := decodeClosedJSON(path, destination)
	if err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	if len(object) != len(expectedKeys) {
		return errors.New("JSON object does not contain the exact required keys")
	}
	for key := range object {
		if !expectedKeys[key] {
			return errors.New("JSON object contains an unexpected key")
		}
	}
	return nil
}

func validateBuilderReceipt(record builderReceipt, expectation pipelineOutputExpectation) error {
	if record.Contract != outputBuilderContract || record.Status != "passed" ||
		record.Candidate != expectation.Candidate || record.Tree != expectation.Tree ||
		record.MakeAppXSHA256 != expectation.MakeAppXSHA256 || record.MSIXVersion != outputVersion ||
		record.PackageFamilyName != outputPackageFamilyName || record.PackageIdentityName != outputPackageIdentityName ||
		record.StoreID != outputStoreID || record.SourceManifestSHA256 != "sha256:"+expectation.SourceManifestSHA256 ||
		record.SourceTreeDigest != "sha256:"+expectation.SourceTreeDigest || !hex64.MatchString(record.MSIXSHA256) ||
		record.PayloadFileCount <= 0 || record.StageFileCount <= 0 ||
		!validPrefixedDigest(record.PayloadTreeDigest) || !validPrefixedDigest(record.StageTreeDigest) {
		return errors.New("builder receipt binding is invalid")
	}
	return nil
}

func validateComparisonReceipt(record comparisonReceipt, expectation pipelineOutputExpectation) error {
	if record.Contract != outputComparisonContract || record.Status != "passed" ||
		record.Candidate != expectation.Candidate || record.Tree != expectation.Tree ||
		record.MakeAppXSHA256 != "sha256:"+expectation.MakeAppXSHA256 ||
		record.ContainerEquivalenceClaimed || record.RawContentSerialized || record.PYCFileCount != 0 ||
		record.VerificationMethod != outputComparisonMethod || !validPrefixedDigest(record.FirstMSIXSHA256) ||
		!validPrefixedDigest(record.SecondMSIXSHA256) || !validPrefixedDigest(record.PackageContentDigest) ||
		record.PackageFileCount <= 0 || record.PayloadFileCount <= 0 || record.PayloadFileCount > record.PackageFileCount {
		return errors.New("semantic comparison receipt binding is invalid")
	}
	return nil
}

func contentSafetyReportDigest(record contentSafetyReceipt) (string, error) {
	body := map[string]any{
		"absolute_paths_serialized": record.AbsolutePathsSerialized,
		"candidate":                 record.Candidate,
		"contract":                  record.Contract,
		"opaque_bound_file_count":   record.OpaqueBoundFileCount,
		"package_content_digest":    record.PackageContentDigest,
		"package_file_count":        record.PackageFileCount,
		"payload_file_count":        record.PayloadFileCount,
		"raw_content_serialized":    record.RawContentSerialized,
		"scanned_text_file_count":   record.ScannedTextFileCount,
		"status":                    record.Status,
		"tree":                      record.Tree,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateContentSafetyReceipt(record contentSafetyReceipt, expectation pipelineOutputExpectation) error {
	expectedReportDigest, err := contentSafetyReportDigest(record)
	if err != nil {
		return err
	}
	if record.Contract != outputContentSafetyContract || record.Status != "passed" ||
		record.Candidate != expectation.Candidate || record.Tree != expectation.Tree ||
		record.AbsolutePathsSerialized || record.RawContentSerialized ||
		!validPrefixedDigest(record.PackageContentDigest) || record.ReportDigest != expectedReportDigest ||
		record.PackageFileCount <= 0 || record.PayloadFileCount <= 0 || record.PayloadFileCount > record.PackageFileCount ||
		record.ScannedTextFileCount <= 0 || record.OpaqueBoundFileCount < 0 ||
		record.OpaqueBoundFileCount+record.ScannedTextFileCount != record.PackageFileCount {
		return errors.New("content-safety receipt binding is invalid")
	}
	return nil
}

func validatePipelineReceipts(root string, inventory []fileBinding, expectation pipelineOutputExpectation) error {
	bindings := outputBindingsByPath(inventory)
	var firstBuilder builderReceipt
	if err := decodeExactClosedJSON(filepath.Join(root, outputFirstBuildName), &firstBuilder, builderReceiptKeys); err != nil {
		return fmt.Errorf("first builder receipt is not canonical and closed: %w", err)
	}
	var secondBuilder builderReceipt
	if err := decodeExactClosedJSON(filepath.Join(root, outputSecondBuildName), &secondBuilder, builderReceiptKeys); err != nil {
		return fmt.Errorf("second builder receipt is not canonical and closed: %w", err)
	}
	var comparison comparisonReceipt
	if err := decodeExactClosedJSON(filepath.Join(root, outputComparisonName), &comparison, comparisonReceiptKeys); err != nil {
		return fmt.Errorf("comparison receipt is not canonical and closed: %w", err)
	}
	var firstContent contentSafetyReceipt
	if err := decodeExactClosedJSON(filepath.Join(root, outputFirstContentSafetyName), &firstContent, contentSafetyReceiptKeys); err != nil {
		return fmt.Errorf("first content-safety receipt is not canonical and closed: %w", err)
	}
	var secondContent contentSafetyReceipt
	if err := decodeExactClosedJSON(filepath.Join(root, outputSecondContentSafetyName), &secondContent, contentSafetyReceiptKeys); err != nil {
		return fmt.Errorf("second content-safety receipt is not canonical and closed: %w", err)
	}
	var result buildResultReceipt
	if err := decodeExactClosedJSON(filepath.Join(root, outputBuildResultName), &result, buildResultReceiptKeys); err != nil {
		return fmt.Errorf("build result is not canonical and closed: %w", err)
	}
	if err := validateBuilderReceipt(firstBuilder, expectation); err != nil {
		return err
	}
	if err := validateBuilderReceipt(secondBuilder, expectation); err != nil {
		return err
	}
	if err := validateComparisonReceipt(comparison, expectation); err != nil {
		return err
	}
	if err := validateContentSafetyReceipt(firstContent, expectation); err != nil {
		return err
	}
	if err := validateContentSafetyReceipt(secondContent, expectation); err != nil {
		return err
	}
	if firstBuilder.PayloadFileCount != secondBuilder.PayloadFileCount ||
		firstBuilder.PayloadTreeDigest != secondBuilder.PayloadTreeDigest ||
		firstBuilder.StageFileCount != secondBuilder.StageFileCount ||
		firstBuilder.StageTreeDigest != secondBuilder.StageTreeDigest {
		return errors.New("independent builder receipts disagree")
	}
	if firstBuilder.MSIXSHA256 != bindings[outputMSIXName].SHA256 ||
		comparison.FirstMSIXSHA256 != prefixedDigest(bindings[outputMSIXName]) ||
		comparison.FirstMSIXSHA256 != "sha256:"+firstBuilder.MSIXSHA256 ||
		comparison.SecondMSIXSHA256 != "sha256:"+secondBuilder.MSIXSHA256 {
		return errors.New("MSIX artifact and build receipts disagree")
	}
	if firstContent != secondContent || firstContent.PackageContentDigest != comparison.PackageContentDigest ||
		firstContent.PackageFileCount != comparison.PackageFileCount || firstContent.PayloadFileCount != comparison.PayloadFileCount {
		return errors.New("content-safety and semantic receipts disagree")
	}
	if result.Contract != outputBuildResultContract || result.Status != "passed" ||
		result.Candidate != expectation.Candidate || result.Tree != expectation.Tree ||
		result.MakeAppXSHA256 != "sha256:"+expectation.MakeAppXSHA256 ||
		result.SourceManifestSHA256 != "sha256:"+expectation.SourceManifestSHA256 ||
		result.SourceTreeDigest != "sha256:"+expectation.SourceTreeDigest ||
		result.PackageIdentityName != outputPackageIdentityName || result.StoreID != outputStoreID ||
		result.NetworkPhase != "none" || result.VerificationMethod != outputBuildResultVerification ||
		result.MSIXSHA256 != prefixedDigest(bindings[outputMSIXName]) ||
		result.PackageContentDigest != comparison.PackageContentDigest ||
		result.ComparisonReceiptSHA256 != prefixedDigest(bindings[outputComparisonName]) ||
		result.FirstBuildReceiptSHA256 != prefixedDigest(bindings[outputFirstBuildName]) ||
		result.SecondBuildReceiptSHA256 != prefixedDigest(bindings[outputSecondBuildName]) ||
		result.FirstContentSafetyReceiptSHA256 != prefixedDigest(bindings[outputFirstContentSafetyName]) ||
		result.SecondContentSafetyReceiptSHA256 != prefixedDigest(bindings[outputSecondContentSafetyName]) {
		return errors.New("build result does not bind the exact artifact and receipts")
	}
	return nil
}

func inspectPipelineOutput(root string, expectation pipelineOutputExpectation) ([]fileBinding, error) {
	inventory, err := pipelineOutputInventory(root)
	if err != nil {
		return nil, err
	}
	if err := validatePipelineReceipts(root, inventory, expectation); err != nil {
		return nil, err
	}
	finalInventory, err := pipelineOutputInventory(root)
	if err != nil {
		return nil, err
	}
	if !sameFileBindings(inventory, finalInventory) {
		return nil, errors.New("pipeline output changed while its receipts were verified")
	}
	return finalInventory, nil
}
