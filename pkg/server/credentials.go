package server

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type LoginCredentials struct{ Email, Password string }
type CredentialsProvider func() (LoginCredentials, error)

func ReadCredential(filename string) (string, error) {
	if filename == "" {
		return "", errors.New("credential file is required")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return "", errors.New("credential file is unavailable")
	}
	private := info.Mode().Perm()&0077 == 0
	// systemd on Ubuntu supplies 0440 files inside a private, read-only
	// credentials directory. Permit its group-read bit only within that directory.
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); !private && dir != "" && filepath.Dir(filename) == filepath.Clean(dir) && info.Mode().Perm()&0037 == 0 {
		if parent, err := os.Lstat(dir); err == nil && parent.IsDir() && parent.Mode().Perm()&0027 == 0 {
			private = true
		}
	}
	if !info.Mode().IsRegular() || !private || info.Size() > 4096 {
		return "", errors.New("credential file must be a private regular file")
	}
	f, err := os.Open(filename)
	if err != nil {
		return "", errors.New("credential file is unavailable")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return "", errors.New("credential file is invalid")
	}
	// Remove the file's line ending without trimming password spaces or punctuation.
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" || strings.ContainsAny(s, "\x00\r\n") {
		return "", errors.New("credential file is empty or contains multiple lines")
	}
	return s, nil
}
func ReadLoginCredentials(emailFile, passwordFile string) (LoginCredentials, error) {
	email, err := ReadCredential(emailFile)
	if err != nil {
		return LoginCredentials{}, err
	}
	password, err := ReadCredential(passwordFile)
	if err != nil {
		return LoginCredentials{}, err
	}
	return LoginCredentials{Email: email, Password: password}, nil
}
