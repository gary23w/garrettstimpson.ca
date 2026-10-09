package noaadapter

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

type fileArchiver struct {
	mu   sync.Mutex
	root string
}

func NewFileArchiver(root string) noa.Archiver { return &fileArchiver{root: root} }

func (a *fileArchiver) Write(tier noa.Tier, blockID, startRef, endRef string, content []byte) (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	rel := filepath.Join(noa.ArchiveTierDir(tier), noa.ArchiveFileName(blockID, startRef, endRef))
	abs := filepath.Join(a.root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", "", fmt.Errorf("create archive dir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(abs), ".noa-*.tmp")
	if err != nil {
		return "", "", fmt.Errorf("create temp archive: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", "", fmt.Errorf("write archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", "", fmt.Errorf("close archive: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return "", "", fmt.Errorf("chmod archive: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		os.Remove(tmpName)
		return "", "", fmt.Errorf("install archive: %w", err)
	}
	return abs, filepath.ToSlash(rel), nil
}

func (a *fileArchiver) Remove(abs string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

type reuseArchiver struct {
	inner noa.Archiver
	root  string
}

func NewReuseArchiver(root string) noa.Archiver {
	return &reuseArchiver{inner: NewFileArchiver(root), root: root}
}

func (a *reuseArchiver) Write(tier noa.Tier, blockID, startRef, endRef string, content []byte) (string, string, error) {
	rel := filepath.Join(noa.ArchiveTierDir(tier), noa.ArchiveFileName(blockID, startRef, endRef))
	abs := filepath.Join(a.root, rel)
	if _, err := os.Stat(abs); err == nil {
		return abs, filepath.ToSlash(rel), nil
	}
	return a.inner.Write(tier, blockID, startRef, endRef, content)
}

func (a *reuseArchiver) Remove(string) error { return nil }
