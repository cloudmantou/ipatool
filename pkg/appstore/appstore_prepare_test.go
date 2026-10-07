package appstore

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"howett.net/plist"
)

func prepareZIP(t *testing.T, platform string, sinfPaths []string, extra []string) *zip.Reader {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	info, _ := plist.Marshal(preparePackageInfo{Executable: "Test", BundleID: "com.example.test", Version: "1.0", Platforms: []string{platform}}, plist.BinaryFormat)
	entries := []PackagePatch{{Path: "Payload/Test.app/Info.plist", Content: info}, {Path: "Payload/Test.app/Test", Content: []byte("executable")}}
	if sinfPaths != nil {
		m, _ := plist.Marshal(packageManifest{SinfPaths: sinfPaths}, plist.BinaryFormat)
		entries = append(entries, PackagePatch{Path: "Payload/Test.app/SC_Info/Manifest.plist", Content: m})
	}
	for _, name := range extra {
		entries = append(entries, PackagePatch{Path: name, Content: []byte("x")})
	}
	for _, p := range entries {
		e, err := w.Create(p.Path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.Write(p.Content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestPrepareSinfMetadataAndManifestMapping(t *testing.T) {
	metadata := map[string]interface{}{"itemId": int64(123)}
	item := downloadItemResult{Metadata: metadata, Sinfs: []Sinf{{Data: []byte("first")}, {Data: []byte("second")}}}
	r := prepareZIP(t, "iPhoneOS", []string{"SC_Info/a.sinf", "SC_Info/b.sinf"}, nil)
	patches, info, err := preparePackagePatches(r, item, Account{Email: "account@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "1.0" || len(patches) != 3 || patches[1].Path != "Payload/Test.app/SC_Info/b.sinf" || string(patches[1].Content) != "second" {
		t.Fatalf("wrong patches: %+v", patches)
	}
	var got map[string]interface{}
	if _, err := plist.Unmarshal(patches[2].Content, &got); err != nil {
		t.Fatal(err)
	}
	if got["apple-id"] != "account@example.com" || metadata["apple-id"] != nil {
		t.Fatal("account metadata mutated shared ticket")
	}
	item.Sinfs = item.Sinfs[:1]
	patches, _, err = preparePackagePatches(prepareZIP(t, "iPhoneOS", nil, nil), item, Account{})
	if err != nil || patches[0].Path != "Payload/Test.app/SC_Info/Test.sinf" {
		t.Fatalf("fallback failed: %v", err)
	}
}
func TestPrepareRejectsWrongPlatformUnsafeAndMissingSinfs(t *testing.T) {
	item := downloadItemResult{Sinfs: []Sinf{{Data: []byte("sinf")}}}
	for _, r := range []*zip.Reader{
		prepareZIP(t, "AppleTVOS", nil, nil), prepareZIP(t, "iPhoneOS", []string{"../evil.sinf"}, nil),
		prepareZIP(t, "iPhoneOS", []string{"SC_Info/a.sinf", "SC_Info/b.sinf"}, nil), prepareZIP(t, "iPhoneOS", nil, []string{"../escape"}),
		prepareZIP(t, "iPhoneOS", nil, []string{"Payload/Test.app/Info.plist"}),
	} {
		if _, _, err := preparePackagePatches(r, item, Account{}); err == nil {
			t.Fatal("unsafe package accepted")
		}
	}
}
func TestAssetURLAndExpiry(t *testing.T) {
	for _, raw := range []string{"http://iosapps.itunes.apple.com/a", "https://apple.com.evil.test/a", "https://user@iosapps.itunes.apple.com/a", "https://localhost/a", "https://iosapps.itunes.apple.com:444/a"} {
		if IsAppleAssetURL(raw) {
			t.Fatalf("accepted %s", raw)
		}
	}
	if !IsAppleAssetURL("https://iosapps.itunes.apple.com/a?token=opaque") {
		t.Fatal("valid Apple ticket rejected")
	}
	if got := downloadURLExpiry("https://iosapps.itunes.apple.com/a?expires=1900000000"); got.Unix() != 1900000000 {
		t.Fatal("expiry lost")
	}
	if got := downloadURLExpiry("https://iosapps.itunes.apple.com/a?X-Amz-Date=20261007T000000Z&X-Amz-Expires=60"); !got.Equal(time.Date(2026, 10, 7, 0, 1, 0, 0, time.UTC)) {
		t.Fatal("AWS expiry lost")
	}
}
func TestServerDownloadSizeBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		_, _ = io.Copy(w, bytes.NewReader(make([]byte, 1024)))
	}))
	defer srv.Close()
	store := &appstore{httpClient: apphttp.NewClient[interface{}](apphttp.Args{}), os: operatingsystem.New()}
	dst := filepath.Join(t.TempDir(), "app.tmp")
	if err := store.downloadFileBounded(context.Background(), srv.URL, dst, nil, 512); err == nil {
		t.Fatal("oversized download accepted")
	}
	info, _ := os.Stat(dst)
	if info.Size() > 512 {
		t.Fatal("size limit exceeded on disk")
	}
}
