package manifest

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"imagelock2hauler/internal/lock"
)

func sampleLock(t *testing.T) *lock.Lock {
	t.Helper()
	data, err := os.ReadFile("../../testdata/fluent-bit.images-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	l, err := lock.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNormalizePlatform(t *testing.T) {
	cases := map[string]string{
		"x86_64": "linux/amd64", "amd64": "linux/amd64", "linux/amd64": "linux/amd64",
		"arm64": "linux/arm64", "aarch64": "linux/arm64", "linux/arm64": "linux/arm64",
	}
	for in, want := range cases {
		got, err := NormalizePlatform(in)
		if err != nil || got != want {
			t.Errorf("NormalizePlatform(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormalizePlatform("windows/386"); err == nil {
		t.Error("unsupported platform: expected error")
	}
}

func TestBuildDigestPinsEverySelectedImageArchPair(t *testing.T) {
	l := sampleLock(t)
	// default: x86_64 only → 2 entries (one per image)
	docs, err := Build(l, Options{Name: "test", Platforms: []string{"linux/amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].Kind != "Images" || docs[1].Kind != "Charts" {
		t.Fatalf("docs = %+v", docs)
	}
	entries := docs[0].Spec.Images
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (amd64 only)", len(entries))
	}
	want := "dp.apps.rancher.io/containers/configmap-reload@sha256:5440865792e84541a53b0924a9c747c11ae319f4bd25ce8143a6c0e446f2e81f"
	if entries[0].Name != want {
		t.Errorf("entry[0] = %q\nwant   = %q", entries[0].Name, want)
	}
	// both platforms → 4 entries
	docs, err = Build(l, Options{Name: "test", Platforms: []string{"linux/amd64", "linux/arm64"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs[0].Spec.Images) != 4 {
		t.Fatalf("entries = %d, want 4", len(docs[0].Spec.Images))
	}
}

func TestBuildRejectsPlatformSelectingNothing(t *testing.T) {
	l := sampleLock(t)
	if _, err := Build(l, Options{Name: "test", Platforms: []string{"linux/riscv64"}}); err == nil {
		t.Error("expected error for platform selecting no images")
	}
}

func TestBuildAnnotationsAreFixed(t *testing.T) {
	l := sampleLock(t)
	docs, err := Build(l, Options{Name: "test", Platforms: []string{"linux/amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	ann := docs[0].Metadata.Annotations
	if ann["hauler.dev/key"] != PubKeyURL {
		t.Errorf("key annotation = %q, want hardcoded %q", ann["hauler.dev/key"], PubKeyURL)
	}
	if ann["hauler.dev/use-tlog-verify"] != "true" {
		t.Error("tlog must always be enabled")
	}
	if ann["hauler.dev/platform"] != "linux/amd64" {
		t.Errorf("platform annotation = %q", ann["hauler.dev/platform"])
	}
}

func TestBuildChartDocAlwaysEmitted(t *testing.T) {
	l := sampleLock(t)
	docs, err := Build(l, Options{Name: "test", Platforms: []string{"linux/amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	chart := docs[1]
	if chart.Kind != "Charts" || len(chart.Spec.Charts) != 1 ||
		chart.Spec.Charts[0].Name != "fluent-bit" ||
		chart.Spec.Charts[0].RepoURL != "oci://dp.apps.rancher.io/charts" ||
		chart.Spec.Charts[0].Version != "0.58.2" {
		t.Errorf("chart doc = %+v", chart)
	}
}

func TestEmitMultiDocYAML(t *testing.T) {
	l := sampleLock(t)
	sum := sha256.Sum256([]byte("x"))
	out, err := Emit(mustBuild(t, l, Options{Name: StoreName(l, sum), Platforms: []string{"linux/amd64"}}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"apiVersion: content.hauler.cattle.io/v1",
		"kind: Images",
		fmt.Sprintf("name: appco-fluent-bit-0.58.2-%x", sum[:4]), // lock-fingerprinted name
		"dp.apps.rancher.io/containers/configmap-reload@sha256:",
		"kind: Charts",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func mustBuild(t *testing.T, l *lock.Lock, opt Options) []Document {
	t.Helper()
	docs, err := Build(l, opt)
	if err != nil {
		t.Fatal(err)
	}
	return docs
}
