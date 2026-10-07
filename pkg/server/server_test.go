package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/majd/ipatool/v2/pkg/appstore"
)

type fakeStore struct {
	account                                 appstore.Account
	accountErr, loginErr                    error
	loginCalls, purchaseCalls, prepareCalls int
	failures                                []error
	lastLogin                               appstore.LoginInput
	price                                   float64
}

func (f *fakeStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	return appstore.AccountInfoOutput{Account: f.account}, f.accountErr
}
func (f *fakeStore) Login(in appstore.LoginInput) (appstore.LoginOutput, error) {
	f.loginCalls++
	f.lastLogin = in
	return appstore.LoginOutput{Account: f.account}, f.loginErr
}
func (f *fakeStore) Lookup(in appstore.LookupInput) (appstore.LookupOutput, error) {
	return appstore.LookupOutput{App: appstore.App{ID: in.AppID, Price: f.price}}, nil
}
func (f *fakeStore) Purchase(appstore.PurchaseInput) error { f.purchaseCalls++; return nil }
func (f *fakeStore) Download(appstore.DownloadInput) (appstore.DownloadOutput, error) {
	return appstore.DownloadOutput{}, errors.New("unused")
}
func (f *fakeStore) ReplicateSinf(appstore.ReplicateSinfInput) error { return nil }
func (f *fakeStore) PrepareDownload(appstore.PrepareDownloadInput) (appstore.PrepareDownloadOutput, error) {
	i := f.prepareCalls
	f.prepareCalls++
	if i < len(f.failures) {
		return appstore.PrepareDownloadOutput{}, f.failures[i]
	}
	return appstore.PrepareDownloadOutput{URL: "https://iosapps.itunes.apple.com/app.ipa", FileSize: 100, Patches: []appstore.PackagePatch{{Path: "iTunesMetadata.plist", Content: []byte("metadata")}}}, nil
}
func testArtifacts(t *testing.T, region string) *ArtifactStore {
	t.Helper()
	s, err := NewArtifactStore(t.TempDir(), "https://"+region+".example.com", region, []byte(strings.Repeat("x", 32)), time.Hour, 1024, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func testResolver(t *testing.T, f *fakeStore) *Resolver {
	t.Helper()
	r, err := NewResolver(f, f, testArtifacts(t, "cn"), func() (LoginCredentials, error) {
		return LoginCredentials{"account@example.com", "credential-password."}, nil
	}, "cn", 1024)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func validAccount() appstore.Account {
	return appstore.Account{StoreFront: "143465-19,29", PasswordToken: "token", DirectoryServicesID: "123"}
}
func TestRefreshAndFreeLicenseRecovery(t *testing.T) {
	f := &fakeStore{account: validAccount(), failures: []error{appstore.ErrPasswordTokenExpired, appstore.ErrLicenseRequired}}
	r := testResolver(t, f)
	_, purchased, err := r.Prepare(context.Background(), "123", "456")
	if err != nil || !purchased || f.loginCalls != 1 || f.purchaseCalls != 1 || f.prepareCalls != 3 {
		t.Fatalf("recovery failed: %v, %+v", err, f)
	}
	if f.lastLogin.Password != "credential-password." {
		t.Fatal("credential punctuation lost")
	}
}
func TestAuthCooldownAndSuccessReset(t *testing.T) {
	f := &fakeStore{account: validAccount(), accountErr: errors.New("missing account"), loginErr: appstore.ErrAuthCodeRequired}
	r := testResolver(t, f)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	_, _, err := r.Prepare(context.Background(), "123", "456")
	var se *ServiceError
	if !errors.As(err, &se) || se.Code != "auth_code_required" {
		t.Fatalf("lost 2FA state: %v", err)
	}
	_, _, _ = r.Prepare(context.Background(), "123", "456")
	if f.loginCalls != 1 {
		t.Fatal("cooldown retried credentials")
	}
	now = now.Add(time.Minute)
	f.loginErr = nil
	if _, _, err := r.Prepare(context.Background(), "123", "456"); err != nil {
		t.Fatal(err)
	}
	if r.failureCount != 0 || !r.failureUntil.IsZero() {
		t.Fatal("success retained cooldown")
	}
}
func TestWrongRegionAndPaidAppNeverProceed(t *testing.T) {
	f := &fakeStore{account: validAccount()}
	f.account.StoreFront = "143441-1"
	r := testResolver(t, f)
	if _, _, err := r.Prepare(context.Background(), "123", "456"); err == nil || f.prepareCalls != 0 {
		t.Fatal("wrong-region account reached download")
	}
	f.account = validAccount()
	f.failures = []error{appstore.ErrLicenseRequired}
	f.price = 0.99
	if _, _, err := r.Prepare(context.Background(), "123", "456"); err == nil || f.purchaseCalls != 0 {
		t.Fatal("paid purchase attempted")
	}
}
func TestCredentialFilesPreservePasswordAndRejectExposure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(p, []byte(" leading and trailing . \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadCredential(p)
	if err != nil || s != " leading and trailing . " {
		t.Fatalf("password modified: %q %v", s, err)
	}
	_ = os.Chmod(p, 0644)
	if _, err := ReadCredential(p); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	link := p + "-link"
	_ = os.Symlink(p, link)
	if _, err := ReadCredential(link); err == nil {
		t.Fatal("credential symlink accepted")
	}
	_ = os.Chmod(p, 0440)
	if _, err := ReadCredential(p); err == nil {
		t.Fatal("group-readable ordinary credential accepted")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Dir(p))
	_ = os.Chmod(filepath.Dir(p), 0550)
	if got, err := ReadCredential(p); err != nil || got != s {
		t.Fatalf("private systemd credential rejected: %v", err)
	}
	_ = os.Chmod(filepath.Dir(p), 0755)
	if _, err := ReadCredential(p); err == nil {
		t.Fatal("public credentials directory accepted")
	}
}
func TestHandlerContractAndInputValidation(t *testing.T) {
	f := &fakeStore{account: validAccount()}
	r := testResolver(t, f)
	h := NewHandler(r, r.Artifacts, nil)
	tests := []struct {
		method, body, content string
		status                int
	}{
		{"POST", `{}`, "application/json", 400}, {"GET", ``, "", 405}, {"POST", `{"appId":"123","appVerId":"456"}`, "text/plain", 415},
		{"POST", `{"appId":123,"appVerId":"456"}`, "application/json", 400}, {"POST", `{"appId":"1","appId":"123","appVerId":"456"}`, "application/json", 400},
		{"POST", `{"appId":"123","appVerId":"456","url":"https://evil.test"}`, "application/json", 400},
		{"POST", `{"appId":"123","appVerId":"456"}{}`, "application/json", 400}, {"POST", `{"appId":"9223372036854775808","appVerId":"456"}`, "application/json", 400},
		{"POST", `{"appId":"123","appVerId":"456"}`, "application/json; charset=utf-8", 200},
	}
	for _, test := range tests {
		req := httptest.NewRequest(test.method, "/api/ipa/prepare", strings.NewReader(test.body))
		req.Header.Set("Content-Type", test.content)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != test.status {
			t.Fatalf("%s => %d: %s", test.body, w.Code, w.Body.String())
		}
		if w.Code == 200 {
			var out struct {
				Success bool
				Data    preparedData
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if !out.Success || out.Data.PackageMode != "client-patch-v1" || out.Data.AppID != "123" || string(out.Data.Patches[0].Content) != "metadata" || len(out.Data.Patches[0].SHA256) != 64 {
				t.Fatalf("contract lost: %+v", out)
			}
		}
	}
}

type blockingService struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingService) Prepare(ctx context.Context, id, v string) (appstore.PrepareDownloadOutput, bool, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return appstore.PrepareDownloadOutput{}, false, errors.New("private-token")
}
func (b *blockingService) Download(context.Context, string, string) (string, bool, error) {
	return "", false, errors.New("unused")
}
func TestHandlerBusyAndErrorRedaction(t *testing.T) {
	b := &blockingService{started: make(chan struct{}), release: make(chan struct{})}
	h := NewHandler(b, http.NotFoundHandler(), nil)
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/ipa/prepare", strings.NewReader(`{"appId":"1","appVerId":"2"}`))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, request()); done <- w }()
	<-b.started
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatal("parallel request was not rejected")
	}
	close(b.release)
	w = <-done
	if strings.Contains(w.Body.String(), "private-token") {
		t.Fatal("upstream secret leaked")
	}
}
func writeTestIPA(dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	w := zip.NewWriter(f)
	entry, err := w.Create("Payload/Test.app/Info.plist")
	if err != nil {
		return err
	}
	_, _ = entry.Write([]byte("plist"))
	if err := w.Close(); err != nil {
		return err
	}
	return f.Close()
}
func TestArtifactExpiryTamperingRegionAndCleanup(t *testing.T) {
	s := testArtifacts(t, "cn")
	now := time.Now().Truncate(time.Second)
	s.now = func() time.Time { return now }
	link, err := s.Build(writeTestIPA)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	get := func(store *ArtifactStore, raw string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		store.ServeHTTP(w, httptest.NewRequest("GET", raw, nil))
		return w
	}
	if w := get(s, u.RequestURI()); w.Code != 200 {
		t.Fatalf("valid link: %d", w.Code)
	}
	q := u.Query()
	q.Set("exp", strconvTime(now.Add(2*time.Hour)))
	u.RawQuery = q.Encode()
	if w := get(s, u.RequestURI()); w.Code != 403 {
		t.Fatal("tampered expiry accepted")
	}
	u, _ = url.Parse(link)
	other := testArtifacts(t, "us")
	if w := get(other, u.RequestURI()); w.Code != 403 {
		t.Fatal("cross-region signature accepted")
	}
	now = now.Add(2 * time.Hour)
	if w := get(s, u.RequestURI()); w.Code != 403 {
		t.Fatal("expired link accepted")
	}
	if _, err := s.Build(writeTestIPA); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(s.root)
	if len(entries) != 1 {
		t.Fatal("expired artifact retained")
	}
	if _, err := s.Build(func(dst string) error { _ = os.WriteFile(dst, []byte("partial"), 0600); return errors.New("failed") }); err == nil {
		t.Fatal("partial build succeeded")
	}
	entries, _ = os.ReadDir(s.root)
	if len(entries) != 1 {
		t.Fatal("partial artifact retained")
	}
}
func strconvTime(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }
