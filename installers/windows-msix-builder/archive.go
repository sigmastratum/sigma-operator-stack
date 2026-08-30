package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxArchiveFiles      = 100_000
	maxArchiveBytes      = int64(2 * 1024 * 1024 * 1024)
	maxArchiveSingleFile = int64(512 * 1024 * 1024)
)

type archiveEntry struct {
	file      *zip.File
	relative  string
	directory bool
}

func validateArchive(reader *zip.Reader) ([]archiveEntry, error) {
	if len(reader.File) == 0 || len(reader.File) > maxArchiveFiles {
		return nil, errors.New("runtime archive file count is outside its bound")
	}
	entries := make([]archiveEntry, 0, len(reader.File))
	kinds := map[string]bool{}
	spellings := map[string]string{}
	explicitEntries := map[string]string{}
	var total int64
	for _, file := range reader.File {
		if file.Flags&1 != 0 || (file.Method != zip.Store && file.Method != zip.Deflate) {
			return nil, errors.New("runtime archive uses an unsupported ZIP feature")
		}
		name := strings.TrimSuffix(file.Name, "/")
		if name == "" {
			return nil, errors.New("runtime archive contains an empty path")
		}
		relative, err := safeRelativePath(name)
		if err != nil || relative != name {
			return nil, errors.New("runtime archive contains an unsafe path")
		}
		mode := file.Mode()
		directory := strings.HasSuffix(file.Name, "/")
		if mode&os.ModeSymlink != 0 || (!directory && !mode.IsRegular()) || (directory && !mode.IsDir()) {
			return nil, errors.New("runtime archive contains an unsupported object type")
		}
		entryFolded := strings.ToLower(relative)
		if previous, exists := explicitEntries[entryFolded]; exists {
			return nil, fmt.Errorf("runtime archive duplicate or case-colliding entry between %q and %q", previous, relative)
		}
		explicitEntries[entryFolded] = relative
		parts := strings.Split(relative, "/")
		for index := 1; index <= len(parts); index++ {
			objectPath := strings.Join(parts[:index], "/")
			objectDirectory := index < len(parts) || directory
			folded := strings.ToLower(objectPath)
			if previous, ok := spellings[folded]; ok {
				if previous != objectPath || kinds[folded] != objectDirectory {
					return nil, fmt.Errorf("runtime archive path collision between %q and %q", previous, objectPath)
				}
				if !objectDirectory {
					return nil, errors.New("runtime archive contains a duplicate file")
				}
				continue
			}
			spellings[folded] = objectPath
			kinds[folded] = objectDirectory
		}
		if !directory {
			size := int64(file.UncompressedSize64)
			if size < 0 || size > maxArchiveSingleFile || total > maxArchiveBytes-size {
				return nil, errors.New("runtime archive exceeds its uncompressed size bound")
			}
			total += size
		}
		entries = append(entries, archiveEntry{file: file, relative: relative, directory: directory})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].relative < entries[right].relative })
	return entries, nil
}

func ensureDirectory(root string, relative string) (string, error) {
	current := root
	if relative == "." || relative == "" {
		return current, nil
	}
	for _, component := range strings.Split(filepath.FromSlash(relative), string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() {
			return "", errors.New("destination directory is invalid")
		}
		reparse, reparseErr := isReparse(current, info)
		if reparseErr != nil || reparse {
			return "", errors.New("destination directory is a reparse object")
		}
		unexpectedStreams, streamErr := hasUnexpectedStreams(current)
		if streamErr != nil || unexpectedStreams {
			return "", errors.New("destination directory contains an alternate data stream")
		}
	}
	return current, nil
}

func extractRuntimeArchive(archivePath string, destination string) error {
	archiveInfo, err := os.Lstat(archivePath)
	if err != nil || !archiveInfo.Mode().IsRegular() {
		return errors.New("runtime archive is not a regular file")
	}
	reparse, err := isReparse(archivePath, archiveInfo)
	if err != nil || reparse {
		return errors.New("runtime archive is a reparse object")
	}
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	entries, err := validateArchive(&reader.Reader)
	if err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	for _, entry := range entries {
		parent := path.Dir(entry.relative)
		if _, err := ensureDirectory(destination, parent); err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.relative))
		if entry.directory {
			if _, err := ensureDirectory(destination, entry.relative); err != nil {
				return err
			}
			continue
		}
		input, err := entry.file.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			input.Close()
			return err
		}
		expected := int64(entry.file.UncompressedSize64)
		written, copyErr := io.Copy(output, io.LimitReader(input, expected+1))
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if copyErr != nil || closeOutputErr != nil || closeInputErr != nil || written != expected {
			return errors.New("runtime archive entry failed exact extraction")
		}
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("runtime archive extraction produced an invalid object")
		}
		reparse, err := isReparse(target, info)
		if err != nil || reparse {
			return errors.New("runtime archive extraction produced a reparse object")
		}
		unexpectedStreams, err := hasUnexpectedStreams(target)
		if err != nil || unexpectedStreams {
			return errors.New("runtime archive extraction produced an alternate data stream")
		}
	}
	return nil
}
