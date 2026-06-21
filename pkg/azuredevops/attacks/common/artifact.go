package common

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
)

// DownloadFromSignedURL downloads content from a pre-authenticated signed URL.
func DownloadFromSignedURL(signedURL string) ([]byte, error) {
	resp, err := http.Get(signedURL) //nolint:gosec // Signed URLs are pre-authenticated by ADO
	if err != nil {
		return nil, fmt.Errorf("downloading from signed URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signed URL returned status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ExtractFilesFromZip extracts all files from a zip archive.
// ADO artifact zips contain files inside a folder named after the artifact.
func ExtractFilesFromZip(zipData []byte) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	files := make(map[string][]byte)
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening file %s in zip: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading file %s from zip: %w", f.Name, err)
		}
		files[filepath.Base(f.Name)] = data
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no files found in artifact zip")
	}

	return files, nil
}
