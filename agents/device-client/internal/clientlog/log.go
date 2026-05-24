package clientlog

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

func DefaultPath(name string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".keyward-ssh", name+".log")
}

func Setup(name string) (string, *os.File, error) {
	path := DefaultPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", nil, err
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetOutput(io.MultiWriter(file, os.Stderr))
	return path, file, nil
}