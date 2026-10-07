package profile

import (
	"bytes"
	"testing"
)

type memoryKeychain map[string][]byte

func (k memoryKeychain) Get(s string) ([]byte, error) { return k[s], nil }
func (k memoryKeychain) Set(s string, b []byte) error { k[s] = b; return nil }
func (k memoryKeychain) Remove(s string) error        { delete(k, s); return nil }
func TestDeployedLayoutAndIsolation(t *testing.T) {
	base := memoryKeychain{"account-ff2082aa78aea80a27cb4fb91f0350153702c16dce790a77f0bb0bfbf6899977": []byte("legacy-cn")}
	cn, _ := Keychain(base, "cn")
	us, _ := Keychain(base, "us")
	got, _ := cn.Get("account")
	if string(got) != "legacy-cn" {
		t.Fatal("legacy account not found")
	}
	if err := us.Set("account", []byte("new-us")); err != nil {
		t.Fatal(err)
	}
	got, _ = cn.Get("account")
	if !bytes.Equal(got, []byte("legacy-cn")) {
		t.Fatal("profiles share account state")
	}
	if err := us.Remove("account"); err != nil {
		t.Fatal(err)
	}
	got, _ = cn.Get("account")
	if string(got) != "legacy-cn" {
		t.Fatal("revoke crossed profiles")
	}
	for _, p := range []string{"../cn", "", "cn/us", "a.b"} {
		if _, err := Directory(t.TempDir(), p); err == nil {
			t.Fatalf("accepted invalid profile %q", p)
		}
	}
}
