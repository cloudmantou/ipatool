package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/majd/ipatool/v2/pkg/appstore"
)

type Service interface {
	Prepare(context.Context, string, string) (appstore.PrepareDownloadOutput, bool, error)
	Download(context.Context, string, string) (string, bool, error)
}
type Handler struct {
	service   Service
	artifacts http.Handler
	slot      chan struct{}
	timeout   time.Duration
	log       func(string)
}
type request struct {
	AppID    string `json:"appId"`
	AppVerID string `json:"appVerId"`
}
type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type response struct {
	Success bool           `json:"success"`
	Data    interface{}    `json:"data,omitempty"`
	Error   *responseError `json:"error,omitempty"`
}
type preparedPatch struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
	SHA256  string `json:"sha256"`
}
type preparedData struct {
	PackageMode    string          `json:"packageMode"`
	RawDownloadURL string          `json:"rawDownloadUrl"`
	ExpiresAt      string          `json:"expiresAt,omitempty"`
	FileSize       int64           `json:"fileSize"`
	AppID          string          `json:"appId"`
	AppVerID       string          `json:"appVerId"`
	AppName        string          `json:"appName,omitempty"`
	BundleID       string          `json:"bundleId,omitempty"`
	AppVersion     string          `json:"appVersion,omitempty"`
	Purchased      bool            `json:"purchased"`
	Patches        []preparedPatch `json:"patches"`
}

func NewHandler(service Service, artifacts http.Handler, log func(string)) http.Handler {
	return &Handler{service: service, artifacts: artifacts, slot: make(chan struct{}, 1), timeout: 15 * time.Minute, log: log}
}
func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, response{Error: &responseError{Code: code, Message: message}})
}
func validIdentifier(s string) bool {
	if s == "" || len(s) > 19 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0
}
func decodeRequest(w http.ResponseWriter, r *http.Request) (request, error) {
	var out request
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, errors.New("expected object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return out, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return out, errors.New("duplicate JSON key")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return out, err
		}
	}
	if _, err := d.Token(); err != nil {
		return out, err
	}
	if _, err := d.Token(); err != io.EOF {
		return out, errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	err = d.Decode(&out)
	return out, err
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/health" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeError(w, 405, "method_not_allowed", "method must be GET")
			return
		}
		writeJSON(w, 200, response{Success: true})
		return
	}
	if len(r.URL.Path) >= len("/api/ipa/artifacts/") && r.URL.Path[:len("/api/ipa/artifacts/")] == "/api/ipa/artifacts/" {
		h.artifacts.ServeHTTP(w, r)
		return
	}
	if r.URL.Path != "/api/ipa/prepare" && r.URL.Path != "/api/ipa/download" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, 405, "method_not_allowed", "method must be POST")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	in, err := decodeRequest(w, r)
	if err != nil {
		writeError(w, 400, "invalid_request", "request body must contain string appId and appVerId")
		return
	}
	if !validIdentifier(in.AppID) || !validIdentifier(in.AppVerID) {
		writeError(w, 400, "invalid_request", "appId and appVerId must be decimal identifiers")
		return
	}
	select {
	case h.slot <- struct{}{}:
		defer func() { <-h.slot }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, 503, "busy", "service is busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	if r.URL.Path == "/api/ipa/download" {
		link, purchased, err := h.service.Download(ctx, in.AppID, in.AppVerID)
		if err != nil {
			h.failure(w, err)
			return
		}
		writeJSON(w, 200, response{Success: true, Data: struct {
			AppID       string `json:"appId"`
			AppVerID    string `json:"appVerId"`
			DownloadURL string `json:"downloadUrl"`
			Purchased   bool   `json:"purchased"`
		}{in.AppID, in.AppVerID, link, purchased}})
		return
	}
	out, purchased, err := h.service.Prepare(ctx, in.AppID, in.AppVerID)
	if err != nil {
		h.failure(w, err)
		return
	}
	if !appstore.IsAppleAssetURL(out.URL) || out.FileSize <= 0 || len(out.Patches) == 0 {
		writeError(w, 502, "invalid_upstream_response", "prepare service returned an invalid descriptor")
		return
	}
	data := preparedData{PackageMode: "client-patch-v1", RawDownloadURL: out.URL, FileSize: out.FileSize, AppID: in.AppID, AppVerID: in.AppVerID, AppName: out.AppName, BundleID: out.BundleID, AppVersion: out.AppVersion, Purchased: purchased, Patches: make([]preparedPatch, 0, len(out.Patches))}
	if !out.ExpiresAt.IsZero() {
		data.ExpiresAt = out.ExpiresAt.UTC().Format(time.RFC3339)
	}
	for _, p := range out.Patches {
		hash := sha256.Sum256(p.Content)
		data.Patches = append(data.Patches, preparedPatch{Path: p.Path, Content: p.Content, SHA256: hex.EncodeToString(hash[:])})
	}
	writeJSON(w, 200, response{Success: true, Data: data})
}
func (h *Handler) failure(w http.ResponseWriter, err error) {
	var se *ServiceError
	if errors.As(err, &se) {
		if se.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(se.RetryAfter.Seconds()))))
		}
		if h.log != nil {
			h.log(se.Code)
		}
		writeError(w, se.Status, se.Code, se.Message)
		return
	}
	if h.log != nil {
		h.log("upstream_failure")
	}
	writeError(w, 502, "upstream_failure", "request could not be completed")
}
