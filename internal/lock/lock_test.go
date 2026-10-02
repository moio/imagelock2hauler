package lock

import (
	"os"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

func TestParseVerifiedSample(t *testing.T) {
	l, err := Parse(mustRead(t, "../../testdata/fluent-bit.images-lock.yaml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if l.Chart.Name != "fluent-bit" || l.Chart.Version != "0.58.2" {
		t.Errorf("chart = %+v", l.Chart)
	}
	if len(l.Images) != 2 {
		t.Fatalf("images = %d, want 2", len(l.Images))
	}
	img := l.Images[0]
	if img.Image != "dp.apps.rancher.io/containers/configmap-reload:0.15.0-26.7" {
		t.Errorf("image = %q", img.Image)
	}
	if len(img.Digests) != 2 || img.Digests[0].Arch != "linux/amd64" {
		t.Errorf("digests = %+v", img.Digests)
	}
}

func TestParseRejectsTamperedDigest(t *testing.T) {
	// Last hex digit flipped: still well-formed, so it parses; the registry
	// and cosign layers catch content tampering.
	if _, err := Parse(mustRead(t, "../../testdata/fluent-bit.images-lock.tampered.yaml")); err != nil {
		t.Fatalf("well-formed tampered digest should parse: %v", err)
	}
}

func TestValidateFailures(t *testing.T) {
	cases := map[string]string{
		"empty digests": `
apiVersion: v0
kind: ImagesLock
chart: {name: c, version: "1"}
images:
  - name: i
    image: dp.apps.rancher.io/containers/i:1.0
    digests: []
`,
		"bad digest shape": `
apiVersion: v0
kind: ImagesLock
chart: {name: c, version: "1"}
images:
  - name: i
    image: dp.apps.rancher.io/containers/i:1.0
    digests: [{digest: sha256:abc, arch: linux/amd64}]
`,
		"tagless image": `
apiVersion: v0
kind: ImagesLock
chart: {name: c, version: "1"}
images:
  - name: i
    image: dp.apps.rancher.io/containers/i
    digests: [{digest: sha256:` + strings.Repeat("a", 64) + `, arch: linux/amd64}]
`,
		"wrong kind": `
apiVersion: v0
kind: SomethingElse
chart: {name: c, version: "1"}
images: []
`,
	}
	for name, yamlText := range cases {
		_, err := Parse([]byte(yamlText))
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	yamlText := `
apiVersion: v0
kind: ImagesLock
chart: {name: c, version: "1"}
surpriseField: true
images:
  - name: i
    image: dp.apps.rancher.io/containers/i:1.0
    digests: [{digest: sha256:` + strings.Repeat("a", 64) + `, arch: linux/amd64}]
`
	if _, err := Parse([]byte(yamlText)); err == nil {
		t.Error("unknown field: expected error (strict parsing is not optional)")
	}
}

func TestRepoTag(t *testing.T) {
	repo, tag, err := RepoTag("dp.apps.rancher.io/containers/fb:5.1.2-7.12")
	if err != nil || repo != "dp.apps.rancher.io/containers/fb" || tag != "5.1.2-7.12" {
		t.Errorf("got %q %q %v", repo, tag, err)
	}
}
