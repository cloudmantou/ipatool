package appstore

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"howett.net/plist"
)

type PrepareDownloadInput struct {
	Context           context.Context
	Account           Account
	App               App
	ExternalVersionID string
	Platform          Platform
	MaxBytes          int64
}
type PackagePatch struct {
	Path    string
	Content []byte
}
type PrepareDownloadOutput struct {
	URL               string
	ExpiresAt         time.Time
	FileSize          int64
	ExternalVersionID string
	AppName           string
	BundleID          string
	AppVersion        string
	Patches           []PackagePatch
}
type DownloadPreparer interface {
	PrepareDownload(PrepareDownloadInput) (PrepareDownloadOutput, error)
}

// IsAppleAssetURL excludes credentials, unusual ports and non-Apple destinations.
func IsAppleAssetURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, suffix := range []string{".apple.com", ".itunes.apple.com", ".mzstatic.com"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// prepareHTTPClient confines range requests and redirect hops to Apple assets.
type prepareHTTPClient struct {
	apphttp.Client[interface{}]
	ctx context.Context
}

func (c prepareHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if !IsAppleAssetURL(req.URL.String()) {
		return nil, errors.New("untrusted Apple asset URL")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !IsAppleAssetURL(r.URL.String()) {
			return errors.New("untrusted asset redirect")
		}
		return nil
	}}
	return client.Do(req.WithContext(c.ctx))
}

func (t *appstore) PrepareDownload(input PrepareDownloadInput) (PrepareDownloadOutput, error) {
	ctx := input.Context
	if ctx == nil {
		ctx = context.Background()
	}
	mac, err := t.machine.MacAddress()
	if err != nil {
		return PrepareDownloadOutput{}, err
	}
	guid, _, err := machineIdentity(mac)
	if err != nil {
		return PrepareDownloadOutput{}, err
	}
	res, _, err := t.sendDownloadProduct(ctx, input.Account, input.App, guid, input.ExternalVersionID, PlatformIPhone)
	if err != nil {
		return PrepareDownloadOutput{}, err
	}
	switch res.Data.FailureType {
	case FailureTypePasswordTokenExpired, FailureTypeSignInRequired, FailureTypeDeviceVerificationFailed, FailureTypeLicenseAlreadyExists:
		return PrepareDownloadOutput{}, ErrPasswordTokenExpired
	case FailureTypeLicenseNotFound:
		return PrepareDownloadOutput{}, ErrLicenseRequired
	}
	if res.Data.FailureType != "" || res.Data.CustomerMessage != "" || len(res.Data.Items) != 1 || res.StatusCode != http.StatusOK {
		return PrepareDownloadOutput{}, errors.New("Apple did not return a download ticket")
	}
	if input.ExternalVersionID != "" {
		if err := validateVersionedDownloadResponse(res, input.App, input.ExternalVersionID, "prepare"); err != nil {
			return PrepareDownloadOutput{}, err
		}
	}
	item := res.Data.Items[0]
	if !IsAppleAssetURL(item.URL) {
		return PrepareDownloadOutput{}, errors.New("untrusted Apple download URL")
	}
	client := prepareHTTPClient{Client: t.httpClient, ctx: ctx}
	rangeReader, size, err := newHTTPRangeReaderAt(client, item.URL)
	if err != nil {
		return PrepareDownloadOutput{}, err
	}
	if size <= 0 || input.MaxBytes <= 0 || size > input.MaxBytes {
		return PrepareDownloadOutput{}, errors.New("IPA exceeds configured size limit")
	}
	reader, err := zip.NewReader(rangeReader, size)
	if err != nil {
		return PrepareDownloadOutput{}, err
	}
	patches, info, err := preparePackagePatches(reader, item, input.Account)
	if err != nil {
		return PrepareDownloadOutput{}, err
	}
	if item.ArtworkURL != "" {
		if !IsAppleAssetURL(item.ArtworkURL) {
			return PrepareDownloadOutput{}, errors.New("untrusted artwork URL")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.ArtworkURL, nil)
		if err != nil {
			return PrepareDownloadOutput{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return PrepareDownloadOutput{}, err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK || len(data) == 0 || len(data) > 8<<20 {
			return PrepareDownloadOutput{}, errors.New("invalid artwork response")
		}
		patches = append(patches, PackagePatch{Path: "iTunesArtwork", Content: data})
	}
	return PrepareDownloadOutput{URL: item.URL, FileSize: size, ExpiresAt: downloadURLExpiry(item.URL), ExternalVersionID: input.ExternalVersionID, AppName: input.App.Name, BundleID: info.BundleID, AppVersion: info.Version, Patches: patches}, nil
}

type preparePackageInfo struct {
	Executable string   `plist:"CFBundleExecutable"`
	BundleID   string   `plist:"CFBundleIdentifier"`
	Version    string   `plist:"CFBundleShortVersionString"`
	Platforms  []string `plist:"CFBundleSupportedPlatforms"`
}

func readPreparePlist(file *zip.File, out interface{}) error {
	if file.UncompressedSize64 > 4<<20 {
		return errors.New("package plist is too large")
	}
	r, err := file.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, 4<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("package plist is too large")
	}
	_, err = plist.Unmarshal(data, out)
	return err
}
func safePackagePath(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\\\x00") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../")
}
func preparePackagePatches(reader *zip.Reader, item downloadItemResult, acc Account) ([]PackagePatch, preparePackageInfo, error) {
	var info preparePackageInfo
	if len(reader.File) > 100000 {
		return nil, info, errors.New("IPA contains too many entries")
	}
	var root string
	var manifest *zip.File
	seen := map[string]bool{}
	for _, f := range reader.File {
		name := strings.TrimSuffix(f.Name, "/")
		if !safePackagePath(name) || seen[f.Name] {
			return nil, info, errors.New("IPA contains unsafe or duplicate paths")
		}
		seen[f.Name] = true
		if isMainAppInfoPlist(f.Name) {
			if root != "" {
				return nil, info, errors.New("IPA contains multiple main apps")
			}
			root = path.Dir(f.Name)
			if err := readPreparePlist(f, &info); err != nil {
				return nil, info, err
			}
		}
	}
	if root == "" || !safePackagePath(info.Executable) || strings.Contains(info.Executable, "/") || info.BundleID == "" {
		return nil, info, errors.New("IPA lacks main application metadata")
	}
	if !seen[root+"/"+info.Executable] {
		return nil, info, errors.New("IPA lacks main executable")
	}
	platformOK := false
	for _, p := range info.Platforms {
		if p == "iPhoneOS" {
			platformOK = true
		}
	}
	if !platformOK {
		return nil, info, errors.New("IPA is not an iOS application")
	}
	for _, f := range reader.File {
		if f.Name == root+"/SC_Info/Manifest.plist" {
			manifest = f
		}
	}
	var sinfPaths []string
	if manifest != nil {
		var m packageManifest
		if err := readPreparePlist(manifest, &m); err != nil {
			return nil, info, err
		}
		sinfPaths = m.SinfPaths
	} else if len(item.Sinfs) > 0 {
		sinfPaths = []string{"SC_Info/" + info.Executable + ".sinf"}
	}
	if len(sinfPaths) != len(item.Sinfs) {
		return nil, info, errors.New("package sinf count does not match manifest")
	}
	patches := make([]PackagePatch, 0, len(sinfPaths)+1)
	patchPaths := map[string]bool{}
	for i, sp := range sinfPaths {
		if !safePackagePath(sp) || !strings.HasPrefix(sp, "SC_Info/") || !strings.HasSuffix(sp, ".sinf") || len(item.Sinfs[i].Data) == 0 || patchPaths[sp] {
			return nil, info, errors.New("invalid package sinf patch")
		}
		patchPaths[sp] = true
		patches = append(patches, PackagePatch{Path: root + "/" + sp, Content: item.Sinfs[i].Data})
	}
	metadata := make(map[string]interface{}, len(item.Metadata)+2)
	for k, v := range item.Metadata {
		metadata[k] = v
	}
	metadata["apple-id"] = acc.Email
	metadata["userName"] = acc.Email
	data, err := plist.Marshal(metadata, plist.BinaryFormat)
	if err != nil {
		return nil, info, err
	}
	patches = append(patches, PackagePatch{Path: "iTunesMetadata.plist", Content: data})
	return patches, info, nil
}
func downloadURLExpiry(raw string) time.Time {
	u, err := url.Parse(raw)
	if err != nil {
		return time.Time{}
	}
	for k, values := range u.Query() {
		if strings.EqualFold(k, "expires") || strings.EqualFold(k, "expiry") || k == "exp" {
			for _, v := range values {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
					return time.Unix(n, 0).UTC()
				}
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					return t
				}
			}
		}
	}
	date, err := time.Parse("20060102T150405Z", u.Query().Get("X-Amz-Date"))
	seconds, secondsErr := strconv.ParseInt(u.Query().Get("X-Amz-Expires"), 10, 64)
	if err == nil && secondsErr == nil && seconds > 0 && seconds <= 604800 {
		return date.Add(time.Duration(seconds) * time.Second)
	}
	return time.Time{}
}
