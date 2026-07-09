package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// FixturesRoot mengembalikan path absolut ke docs/fixtures/v3 dari repo root.
func FixturesRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// packages/go-sdk/testutil/fixtures.go -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "fixtures", "v3"))
}

func LoadJSON(path string, out interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func ListJSONFiles(subdir string) ([]string, error) {
	dir := filepath.Join(FixturesRoot(), subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files, nil
}
