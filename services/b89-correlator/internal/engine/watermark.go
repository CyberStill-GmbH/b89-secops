package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A single serving writer owns this directory. Only a fully consumed window advances it.
func loadWatermark(path string) (time.Time, error) {
	if path == "" {
		return time.Time{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
}

func saveWatermark(path string, through time.Time) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".watermark-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(through.UTC().Format(time.RFC3339Nano) + "\n")
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
