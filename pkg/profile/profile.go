// Package profile preserves the deployed region-specific account and cookie layout.
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/majd/ipatool/v2/pkg/keychain"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func ID(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", fmt.Errorf("invalid profile name")
	}
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:]), nil
}

func Directory(root, name string) (string, error) {
	id, err := ID(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "profiles", id), nil
}

type scopedKeychain struct {
	base keychain.Keychain
	id   string
}

func Keychain(base keychain.Keychain, name string) (keychain.Keychain, error) {
	id, err := ID(name)
	if err != nil {
		return nil, err
	}
	return &scopedKeychain{base: base, id: id}, nil
}
func (k *scopedKeychain) key(key string) string             { return key + "-" + k.id }
func (k *scopedKeychain) Get(key string) ([]byte, error)    { return k.base.Get(k.key(key)) }
func (k *scopedKeychain) Set(key string, data []byte) error { return k.base.Set(k.key(key), data) }
func (k *scopedKeychain) Remove(key string) error           { return k.base.Remove(k.key(key)) }
