package intel

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing/fstest"
)

// A bundle is a ZIP holding exactly manifest.json and snapshot.json.gz.
// It is the single-file form used for manual import and server distribution.

// MaxBundleBytes caps an imported or downloaded bundle.
const MaxBundleBytes = MaxPayloadGzBytes + MaxManifestBytes + (1 << 20)

// MakeBundle zips a snapshot directory.
func MakeBundle(dir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{ManifestFile, PayloadFile} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(b); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// OpenBundle reads a bundle into an in-memory FS. Only the two expected file
// names are accepted; anything else (paths, extra files) rejects the bundle.
func OpenBundle(b []byte) (fstest.MapFS, error) {
	if len(b) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds size limit")
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("not a valid snapshot bundle (ZIP): %w", err)
	}
	limits := map[string]int64{ManifestFile: MaxManifestBytes, PayloadFile: MaxPayloadGzBytes}
	out := fstest.MapFS{}
	for _, f := range zr.File {
		limit, ok := limits[f.Name]
		if !ok {
			return nil, fmt.Errorf("unexpected file %q in bundle", f.Name)
		}
		if _, dup := out[f.Name]; dup {
			return nil, fmt.Errorf("duplicate %q in bundle", f.Name)
		}
		if f.UncompressedSize64 > uint64(limit) {
			return nil, fmt.Errorf("%s exceeds size limit", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, limit+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%s exceeds size limit", f.Name)
		}
		out[f.Name] = &fstest.MapFile{Data: data, Mode: 0o600}
	}
	if out[ManifestFile] == nil || out[PayloadFile] == nil {
		return nil, fmt.Errorf("bundle must contain %s and %s", ManifestFile, PayloadFile)
	}
	return out, nil
}
