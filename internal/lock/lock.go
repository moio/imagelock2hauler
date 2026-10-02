// Package lock parses and validates SUSE Application Collection ImagesLock
// files (HIP-0019 draft format as emitted by AppCo).
//
// There is no published spec for the AppCo variant, so parsing is strict by
// default: unknown fields are rejected so that upstream schema drift fails
// loudly instead of silently losing digests.
package lock

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"go.yaml.in/yaml/v4"
)

const (
	ExpectedAPIVersion = "v0"
	ExpectedKind       = "ImagesLock"
)

// Lock is the root document of an images-lock.yaml file.
type Lock struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Chart      Chart    `yaml:"chart"`
	Images     []Image  `yaml:"images"`
}

type Metadata struct {
	GeneratedAt string `yaml:"generatedAt"`
	GeneratedBy string `yaml:"generatedBy"`
}

type Chart struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	AppVersion string `yaml:"appVersion"`
}

type Image struct {
	Name    string   `yaml:"name"`    // short name, e.g. "configmap-reload"
	Image   string   `yaml:"image"`   // repository:tag, e.g. "dp.apps.rancher.io/containers/configmap-reload:0.15.0-26.7"
	Chart   string   `yaml:"chart"`   // chart that references this image
	Digests []Digest `yaml:"digests"` // per-architecture manifest digests
}

type Digest struct {
	Digest string `yaml:"digest"` // sha256:<64 hex>, of the single-arch manifest
	Arch   string `yaml:"arch"`   // e.g. linux/amd64
}

var (
	imageRefRe = regexp.MustCompile(`^[a-zA-Z0-9.\-]+(:[0-9]+)?/[a-zA-Z0-9.\-_/]+:[a-zA-Z0-9.\-_]+$`)
	digestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	archRe     = regexp.MustCompile(`^[a-zA-Z0-9]+/[a-zA-Z0-9]+$`)
)

// Parse decodes and validates a lock file. Unknown fields are always
// rejected, so upstream schema drift is caught immediately instead of
// silently losing digests.
func Parse(data []byte) (*Lock, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var l Lock
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("decoding images-lock: %w", err)
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

// Validate enforces the invariants the conversion relies on. It fails loudly
// rather than letting integrity be silently lost (e.g. an image with no
// digests).
func (l *Lock) Validate() error {
	if l.APIVersion != ExpectedAPIVersion {
		return fmt.Errorf("apiVersion %q: want %q", l.APIVersion, ExpectedAPIVersion)
	}
	if l.Kind != ExpectedKind {
		return fmt.Errorf("kind %q: want %q", l.Kind, ExpectedKind)
	}
	if l.Chart.Name == "" || l.Chart.Version == "" {
		return errors.New("chart.name and chart.version are required")
	}
	if len(l.Images) == 0 {
		return errors.New("no images")
	}
	for i, img := range l.Images {
		where := fmt.Sprintf("images[%d]", i)
		if img.Name == "" {
			return fmt.Errorf("%s: empty name", where)
		}
		if !imageRefRe.MatchString(img.Image) {
			return fmt.Errorf("%s: image %q is not registry/repo:tag", where, img.Image)
		}
		if len(img.Digests) == 0 {
			return fmt.Errorf("%s (%s): no digests — integrity would be silently lost", where, img.Image)
		}
		for j, d := range img.Digests {
			if !digestRe.MatchString(d.Digest) {
				return fmt.Errorf("%s: digests[%d] %q is not sha256:<64 hex>", where, j, d.Digest)
			}
			if !archRe.MatchString(d.Arch) {
				return fmt.Errorf("%s: digests[%d] arch %q is not os/arch", where, j, d.Arch)
			}
		}
	}
	return nil
}

// RepoTag splits "registry/repo:tag" into its two halves.
func RepoTag(imageRef string) (repo, tag string, err error) {
	i := bytes.LastIndexByte([]byte(imageRef), ':')
	if i < 0 {
		return "", "", fmt.Errorf("image %q has no tag", imageRef)
	}
	return imageRef[:i], imageRef[i+1:], nil
}
