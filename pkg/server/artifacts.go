package server

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ArtifactStore struct {
	root, base, namespace string
	secret                []byte
	ttl                   time.Duration
	maxBytes, maxStorage  int64
	mu                    sync.Mutex
	now                   func() time.Time
}

var artifactID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func NewArtifactStore(root, base, namespace string, secret []byte, ttl time.Duration, maxBytes, maxStorage int64) (*ArtifactStore, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !filepath.IsAbs(root) || len(secret) < 32 || ttl <= 0 || maxBytes <= 0 || maxStorage < maxBytes {
		return nil, errors.New("invalid artifact configuration")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("artifact root must be a directory")
	}
	return &ArtifactStore{root: root, base: strings.TrimRight(base, "/"), namespace: namespace, secret: append([]byte(nil), secret...), ttl: ttl, maxBytes: maxBytes, maxStorage: maxStorage, now: time.Now}, nil
}
func (s *ArtifactStore) signature(id, exp string) string {
	h := hmac.New(sha256.New, s.secret)
	fmt.Fprintf(h, "%s\n%s\n%s\napp.ipa", s.namespace, id, exp)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *ArtifactStore) cleanup() (int64, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return 0, err
	}
	var used int64
	for _, entry := range entries {
		if !artifactID.MatchString(entry.Name()) {
			continue
		}
		p := filepath.Join(s.root, entry.Name())
		info, err := os.Lstat(filepath.Join(p, "app.ipa"))
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if s.now().After(info.ModTime().Add(s.ttl)) {
			if err := os.RemoveAll(p); err != nil {
				return 0, err
			}
			continue
		}
		used += info.Size()
	}
	return used, nil
}
func (s *ArtifactStore) Build(build func(string) error) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	used, err := s.cleanup()
	if err != nil {
		return "", err
	}
	if used > s.maxStorage-s.maxBytes {
		return "", errors.New("artifact storage capacity reached")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	dir := filepath.Join(s.root, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	dst := filepath.Join(dir, "app.ipa")
	if err := build(dst); err != nil {
		return "", err
	}
	info, err := os.Lstat(dst)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > s.maxBytes {
		return "", errors.New("invalid or oversized IPA artifact")
	}
	reader, err := zip.OpenReader(dst)
	if err != nil {
		return "", errors.New("artifact is not an IPA archive")
	}
	main := false
	for _, f := range reader.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			main = true
		}
	}
	_ = reader.Close()
	if !main {
		return "", errors.New("artifact lacks a main application")
	}
	now := s.now()
	if err := os.Chtimes(dst, now, now); err != nil {
		return "", err
	}
	if err := os.Chmod(dst, 0600); err != nil {
		return "", err
	}
	exp := strconv.FormatInt(now.Add(s.ttl).Unix(), 10)
	q := url.Values{"exp": {exp}, "sig": {s.signature(id, exp)}}
	success = true
	return s.base + "/api/ipa/artifacts/" + id + "/app.ipa?" + q.Encode(), nil
}
func (s *ArtifactStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", 405)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/ipa/artifacts/"), "/")
	if len(parts) != 2 || !artifactID.MatchString(parts[0]) || parts[1] != "app.ipa" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	q := r.URL.Query()
	exp := q.Get("exp")
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || len(q["exp"]) != 1 || len(q["sig"]) != 1 || s.now().Unix() >= expires || !hmac.Equal([]byte(q.Get("sig")), []byte(s.signature(id, exp))) {
		http.Error(w, "invalid or expired artifact link", 403)
		return
	}
	p := filepath.Join(s.root, id, "app.ipa")
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || expires > info.ModTime().Add(s.ttl).Unix() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="app.ipa"`)
	http.ServeContent(w, r, "app.ipa", info.ModTime(), f)
}
