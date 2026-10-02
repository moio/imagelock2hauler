// Package manifest builds Hauler manifests (content.hauler.cattle.io/v1) from
// a validated ImagesLock.
package manifest

import (
	"bytes"
	"fmt"
	"strings"

	"imagelock2hauler/internal/lock"

	"go.yaml.in/yaml/v4"
)

const APIVersion = "content.hauler.cattle.io/v1"

// PubKeyURL is SUSE's published cosign public key, used for sync-time
// signature verification (hauler accepts URLs for hauler.dev/key).
const PubKeyURL = "https://apps.rancher.io/ap-pubkey.pem"

// Options control how the manifest is built.
type Options struct {
	Name      string   // metadata.name of the primary Images doc
	Platforms []string // canonical os/arch list; entries are filtered to these
	PinTag    bool     // pin by tag instead of digest (degrades integrity; discouraged)
}

// Document is one YAML document (hauler allows multi-doc files).
type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type Spec struct {
	Images []ImageEntry `yaml:"images,omitempty"`
	Charts []ChartEntry `yaml:"charts,omitempty"` // plural: matches hauler's spec.images
}

type ImageEntry struct {
	Name string `yaml:"name"` // repo@sha256:... (digest-pinned) or repo:tag
}

type ChartEntry struct {
	Name     string `yaml:"name"`
	RepoURL  string `yaml:"repoURL"`
	Version  string `yaml:"version"`
	Platform string `yaml:"platform,omitempty"`
}

type FileEntry struct {
	Path string `yaml:"path"`
	Name string `yaml:"name,omitempty"`
}

// ChartRepoURL is the OCI repository AppCo publishes charts to.
const ChartRepoURL = "oci://dp.apps.rancher.io/charts"

// NormalizePlatform accepts common spellings of a platform and returns the
// canonical os/arch form used in lock files and hauler annotations.
func NormalizePlatform(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "x86_64", "amd64", "linux/amd64", "linux/x86_64":
		return "linux/amd64", nil
	case "aarch64", "arm64", "linux/arm64", "linux/aarch64":
		return "linux/arm64", nil
	}
	return "", fmt.Errorf("unsupported platform %q (want x86_64, arm64, or os/arch)", p)
}

// NormalizePlatforms maps a user-supplied list through NormalizePlatform.
func NormalizePlatforms(list []string) ([]string, error) {
	var out []string
	for _, p := range list {
		c, err := NormalizePlatform(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Build converts a validated lock into Hauler manifest documents:
//
//   - Images: one digest-pinned entry per (image, arch) selected by
//     Options.Platforms. No per-entry platform field — hauler auto-detects it,
//     verified live.
//   - Charts: always emitted for the chart itself. Tag-pinned (the lock has no
//     chart digest); authenticity is still enforced by cosign key verification.
//   - The tlog + key verification annotations always match AppCo's documented
//     cosign verification (key-based with Rekor tlog).
//
// rewrite/local/keyless fields are never emitted.
func Build(l *lock.Lock, opt Options) ([]Document, error) {
	imagesDoc := Document{
		APIVersion: APIVersion,
		Kind:       "Images",
		Metadata: Metadata{
			Name:        opt.Name,
			Annotations: verificationAnnotations(opt.Platforms),
		},
	}
	for _, img := range l.Images {
		repo, _, err := lock.RepoTag(img.Image)
		if err != nil {
			return nil, err // unreachable: Validate already checked the ref shape
		}
		for _, d := range img.Digests {
			if !selected(opt.Platforms, d.Arch) {
				continue
			}
			ref := repo + "@" + d.Digest
			if opt.PinTag {
				ref = img.Image // repository:tag — loses digest pinning
			}
			imagesDoc.Spec.Images = append(imagesDoc.Spec.Images, ImageEntry{Name: ref})
		}
	}
	if len(imagesDoc.Spec.Images) == 0 {
		return nil, fmt.Errorf("platforms %v select no images from the lock", opt.Platforms)
	}

	docs := []Document{imagesDoc}

	docs = append(docs, Document{
		APIVersion: APIVersion,
		Kind:       "Charts",
		Metadata: Metadata{
			Name:        opt.Name + "-chart",
			Annotations: verificationAnnotations(opt.Platforms),
		},
		Spec: Spec{Charts: []ChartEntry{{
			Name:    l.Chart.Name,
			RepoURL: ChartRepoURL,
			Version: l.Chart.Version,
		}}},
	})
	return docs, nil
}

// selected reports whether arch is in the canonical platform list.
func selected(platforms []string, arch string) bool {
	for _, p := range platforms {
		if p == arch {
			return true
		}
	}
	return false
}

// verificationAnnotations encodes AppCo's documented cosign verification
// (key-based with Rekor tlog) as hauler manifest annotations.
func verificationAnnotations(platforms []string) map[string]string {
	ann := map[string]string{
		"hauler.dev/key":             PubKeyURL,
		"hauler.dev/use-tlog-verify": "true",
	}
	if len(platforms) > 0 {
		ann["hauler.dev/platform"] = strings.Join(platforms, ",")
	}
	return ann
}

// Emit renders documents as a multi-doc YAML file.
func Emit(docs []Document) ([]byte, error) {
	var buf bytes.Buffer
	for i, doc := range docs {
		if i > 0 {
			buf.WriteString("---\n")
		}
		b, err := yaml.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("marshaling %s doc: %w", doc.Kind, err)
		}
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// StoreName derives the manifest metadata.name from the lock: stable,
// human-readable, and fingerprinted with the lock's own sha256 so a haul
// always records which exact lock file produced it.
func StoreName(l *lock.Lock, lockSHA256 [32]byte) string {
	return fmt.Sprintf("appco-%s-%s-%x", l.Chart.Name, l.Chart.Version, lockSHA256[:4])
}
