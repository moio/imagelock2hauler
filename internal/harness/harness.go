// Package harness runs the automated end-to-end verification:
// fetch a live AppCo lock, convert it, and prove — with recorded evidence —
// that the Hauler flow preserves the integrity and authenticity guarantees of
// AppCo's documented cosign flow.
package harness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"imagelock2hauler/internal/lock"
	"imagelock2hauler/internal/manifest"
)

// PubKeyURL is SUSE's published cosign public key (same constant as the
// converter's hauler.dev/key annotation).
const PubKeyURL = manifest.PubKeyURL

// DefaultPlatforms is the converter's default platform selection, which the
// harness exercises end-to-end.
var DefaultPlatforms = []string{"linux/amd64"} // --platform x86_64

type Config struct {
	Lock       string // https URL or local path of the ImagesLock
	Workdir    string // fresh directory; store, evidence, credentials live here
	ConvertBin string // path to the imagelock2hauler CLI binary
	Registry   string // registry to authenticate against (default dp.apps.rancher.io)
	User       string // registry credentials, from APPCO_USER
	Token      string // registry credentials, from APPCO_TOKEN
}

// Record is one external command invocation. Every invocation is recorded
// with its explicit argv so the evidence is reproducible.
type Record struct {
	Cmd  string `json:"cmd"`
	Exit int    `json:"exit"`
	Note string `json:"note,omitempty"`
}

// Step is one harness phase and its evidence.
type Step struct {
	Name   string   `json:"name"`
	OK     bool     `json:"ok"`
	Detail string   `json:"detail,omitempty"`
	Cmds   []Record `json:"cmds,omitempty"`
}

type storeArtifact struct {
	Reference string `json:"reference"`
	Type      string `json:"type"` // image | chart | atts | sigs | ...
	Platform  string `json:"platform"`
	Digest    string `json:"digest"`
}

// Run executes all steps. It returns a non-nil error if any step failed.
func Run(cfg Config) error {
	if cfg.Registry == "" {
		cfg.Registry = "dp.apps.rancher.io"
	}
	h := &harness{cfg: cfg}
	h.dockerCfg = filepath.Join(cfg.Workdir, "docker")      // crane/cosign credentials
	h.sigstoreRoot = filepath.Join(cfg.Workdir, "sigstore") // cosign TUF cache
	h.storePath = filepath.Join(cfg.Workdir, "store")
	h.haulerdir = filepath.Join(cfg.Workdir, "haulerdir")
	h.pubKeyPath = filepath.Join(cfg.Workdir, "ap-pubkey.pem")
	shimDir := filepath.Join(cfg.Workdir, "bin")
	for _, p := range []string{h.dockerCfg, h.sigstoreRoot, h.storePath, h.haulerdir, filepath.Dir(h.pubKeyPath), shimDir} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
	}
	if err := writeKeychainShim(shimDir); err != nil {
		return err
	}
	h.shimDir = shimDir
	if err := download(PubKeyURL, h.pubKeyPath); err != nil {
		return fmt.Errorf("downloading publisher key: %w", err)
	}

	for _, s := range []struct {
		name string
		fn   func() error
	}{
		{"1-fetch-lock", h.fetchLock},
		{"2-convert", h.convert},
		{"3-reference-flow", h.referenceFlow},
		{"4-hauler-sync", h.haulerSync},
		{"5-parity", h.parity},
		{"6-negative", h.negative},
	} {
		h.begin(s.name)
		if err := s.fn(); err != nil {
			h.fail(err.Error())
		}
	}

	preVerdictFailures := h.failedSteps()
	h.begin("7-verdict")
	if len(preVerdictFailures) > 0 {
		h.fail("failed steps: " + strings.Join(preVerdictFailures, ", "))
	} else {
		h.ok("all success criteria met (see checklist in EVIDENCE.md)")
	}
	mdPath := h.writeEvidence()
	fmt.Printf("== evidence: %s\n", mdPath)
	if !h.cur.OK {
		return h.cur.err()
	}
	return nil
}

type harness struct {
	cfg        Config
	steps      []*Step
	cur        *Step
	l          *lock.Lock
	lockSHA    string
	platforms  []string // canonical platforms under test
	pubKeyPath string   // downloaded copy of PubKeyURL (for cosign/hauler CLIs)
	// paths inside the workdir, initialized by Run
	manifestPath string // converted.yaml
	storePath    string
	haulerdir    string
	dockerCfg    string
	sigstoreRoot string
	lockBytes    []byte
	shimDir      string // prepended to child PATH; neutralizes the macOS keychain credential helper
}

// childEnv is the environment recipe applied to every external command.
// The shim dir goes first on PATH: on macOS, helm's registry client
// (used by hauler for kind=Charts fetches) probes docker-credential-osxkeychain,
// which fails on hosts without keychain access (sandboxes, CI, headless) and —
// because that error aborts credential resolution before the DOCKER_CONFIG file
// store is consulted — breaks every chart fetch with an oras "-50" error. The
// shim answers the docker helper protocol's documented "credentials not found"
// response, so resolution falls through to the real credentials in DOCKER_CONFIG.
func (h *harness) childEnv() []string {
	path := h.shimDir + ":" + os.Getenv("PATH")
	return append(os.Environ(),
		"DOCKER_CONFIG="+h.dockerCfg,
		"TUF_ROOT="+h.sigstoreRoot,
		"COSIGN_PASSWORD=",
		"PATH="+path,
	)
}

// writeKeychainShim installs the docker-credential-osxkeychain shim described
// in childEnv.
func writeKeychainShim(dir string) error {
	shim := `#!/bin/sh
# "credentials not found in native keychain" + exit 1 is the docker credential
# helper protocol's clean no-credentials answer; oras maps it to an empty
# credential instead of an error, so the DOCKER_CONFIG file store is used.
echo "credentials not found in native keychain"
exit 1
`
	return os.WriteFile(filepath.Join(dir, "docker-credential-osxkeychain"), []byte(shim), 0o755)
}

func (h *harness) begin(name string) {
	h.cur = &Step{Name: name}
	h.steps = append(h.steps, h.cur)
	fmt.Printf("== %s\n", name)
}

func (h *harness) ok(detail string) {
	h.cur.OK, h.cur.Detail = true, detail
	fmt.Printf("   PASS %s\n", detail)
}

func (h *harness) fail(detail string) {
	h.cur.OK = false
	if h.cur.Detail != "" {
		detail = h.cur.Detail + "; " + detail
	}
	h.cur.Detail = detail
	fmt.Printf("   FAIL %s\n", detail)
}

func (s *Step) err() error {
	return fmt.Errorf("step %s failed: %s", s.Name, s.Detail)
}

func (h *harness) failedSteps() []string {
	var failed []string
	for _, s := range h.steps {
		if !s.OK {
			failed = append(failed, s.Name)
		}
	}
	return failed
}

// cmd runs an external binary (the real user-facing tools), records argv and
// exit status, and returns combined output. The environment recipe is
// applied automatically.
func (h *harness) cmd(note string, argv ...string) (int, string) {
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = h.childEnv()
	out, err := c.CombinedOutput()
	exit := 0
	if err != nil {
		exit = 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	h.cur.Cmds = append(h.cur.Cmds, Record{Cmd: strings.Join(argv, " "), Exit: exit, Note: note})
	return exit, string(out)
}

// cmdStdin is cmd, with stdin fed from data (for the converter CLI).
// Returns the CLI's **stdout** (the manifest); stderr is recorded separately
// so the audit sha256(line) never contaminates the manifest bytes.
func (h *harness) cmdStdin(note string, stdin []byte, argv ...string) (int, string) {
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = h.childEnv()
	c.Stdin = strings.NewReader(string(stdin))
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	exit := 0
	if err != nil {
		exit = 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
	}
	rec := Record{Cmd: fmt.Sprintf("%s < <lock>", strings.Join(argv, " ")), Exit: exit, Note: note}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		rec.Note += " — stderr: " + s
	}
	h.cur.Cmds = append(h.cur.Cmds, rec)
	return exit, stdout.String()
}

// ---------------------------------------------------------------- steps ----

// fetchLock loads the lock (URL or file), records its sha256 and validates it.
func (h *harness) fetchLock() error {
	data, err := readSource(h.cfg.Lock)
	if err != nil {
		return err
	}
	h.lockBytes = data
	sum := sha256.Sum256(data)
	h.lockSHA = hex.EncodeToString(sum[:])
	l, err := lock.Parse(data)
	if err != nil {
		return err
	}
	h.l = l
	h.platforms = DefaultPlatforms
	pairs := 0
	for _, img := range l.Images {
		for _, d := range img.Digests {
			for _, p := range h.platforms {
				if p == d.Arch {
					pairs++
				}
			}
		}
	}
	h.ok(fmt.Sprintf("chart=%s version=%s images=%d selected-pairs=%v sha256(lock)=%s…",
		l.Chart.Name, l.Chart.Version, len(l.Images), pairs, h.lockSHA[:16]))
	return nil
}

// convert builds the manifest in-process AND via the CLI binary (lock piped
// to stdin); both must be byte-identical so library and CLI stay honest.
func (h *harness) convert() error {
	sum := sha256.Sum256(h.lockBytes)
	name := manifest.StoreName(h.l, sum)
	docs, err := manifest.Build(h.l, manifest.Options{
		Name:      name,
		Platforms: h.platforms,
	})
	if err != nil {
		return err
	}
	inProcess, err := manifest.Emit(docs)
	if err != nil {
		return err
	}
	h.manifestPath = filepath.Join(h.cfg.Workdir, "converted.yaml")
	if err := os.WriteFile(h.manifestPath, inProcess, 0o644); err != nil {
		return err
	}

	exit, out := h.cmdStdin("converter CLI on the same lock", h.lockBytes, h.cfg.ConvertBin)
	if exit != 0 {
		return fmt.Errorf("converter CLI failed: %s", out)
	}
	if out != string(inProcess) {
		return fmt.Errorf("in-process conversion and CLI output differ (byte comparison)")
	}
	h.ok(fmt.Sprintf("%s: %d digest-pinned image entries (platforms %v); CLI output byte-identical to in-process conversion",
		name, len(docs[0].Spec.Images), h.platforms))
	return nil
}

// expectedDigests returns the lock digests selected by the platforms under test.
func (h *harness) expectedDigests() map[string]string { // digest -> repo
	out := map[string]string{}
	for _, img := range h.l.Images {
		repo, _, err := lock.RepoTag(img.Image)
		if err != nil {
			continue // already validated
		}
		for _, d := range img.Digests {
			for _, p := range h.platforms {
				if p == d.Arch {
					out[d.Digest] = repo
				}
			}
		}
	}
	return out
}

// referenceFlow is the ground truth: AppCo's documented verification, run
// directly against the registry with crane + cosign.
func (h *harness) referenceFlow() error {
	if exit, out := h.cmd("registry login",
		"crane", "auth", "login", h.cfg.Registry, "-u", h.cfg.User, "-p", h.cfg.Token); exit != 0 {
		return fmt.Errorf("crane auth login: %s", out)
	}

	verified, mismatches := 0, []string{}
	for _, img := range h.l.Images {
		repo, tag, err := lock.RepoTag(img.Image)
		if err != nil {
			return err
		}
		for _, d := range img.Digests {
			if !h.selected(d.Arch) {
				continue
			}
			// integrity: live per-arch digest must equal the lock's digest
			exit, out := h.cmd("live digest vs lock", "crane", "digest", "--platform", d.Arch, repo+":"+tag)
			got := strings.TrimSpace(out)
			if exit != 0 || got != d.Digest {
				mismatches = append(mismatches, fmt.Sprintf("%s %s/%s: registry=%q lock=%q", img.Image, d.Arch, d.Digest, got, d.Digest))
				continue
			}
			// authenticity: SUSE key + embedded tlog entry
			if exit, out := h.cmd("cosign verify (key+tlog)",
				"cosign", "verify", "--key", h.pubKeyPath, repo+"@"+d.Digest); exit != 0 {
				mismatches = append(mismatches, fmt.Sprintf("cosign verify %s@%s: %s", repo, d.Digest, out))
				continue
			}
			verified++
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("reference flow failures: %s", strings.Join(mismatches, " | "))
	}
	h.ok(fmt.Sprintf("%d image×arch digests match the live registry and verify with SUSE key + tlog", verified))
	return nil
}

// selected reports whether arch is among the platforms under test.
func (h *harness) selected(arch string) bool {
	for _, p := range h.platforms {
		if p == arch {
			return true
		}
	}
	return false
}

func (h *harness) haulerSync() error {
	if exit, out := h.cmd("hauler login", "hauler", "login", h.cfg.Registry,
		"-u", h.cfg.User, "-p", h.cfg.Token, "-d", h.haulerdir); exit != 0 {
		return fmt.Errorf("hauler login: %s", out)
	}
	exit, out := h.cmd("hauler store sync (key + tlog, never --ignore-errors)", "hauler", "store", "sync",
		"-f", h.manifestPath,
		"-k", h.pubKeyPath,
		"--use-tlog-verify",
		"-s", h.storePath,
		"-d", h.haulerdir,
		"--no-progress")
	if exit != 0 {
		return fmt.Errorf("hauler store sync failed: %s", out)
	}
	sigLines := len(regexp.MustCompile(`✓ signature verified`).FindAllString(out, -1))
	h.ok(fmt.Sprintf("full manifest synced (images + chart) with key + tlog verification; %d \"signature verified\" lines in hauler output", sigLines))
	return nil
}

// parity compares store contents against the lock and the live registry.
func (h *harness) parity() error {
	// Blob integrity of the whole store (hashes every blob; slow but definitive).
	if exit, out := h.cmd("store blob integrity check", "hauler", "store", "info",
		"--check", "-s", h.storePath, "-d", h.haulerdir, "-o", "json"); exit != 0 {
		return fmt.Errorf("hauler store info --check: %s", out)
	}

	exit, out := h.cmd("store inventory", "hauler", "store", "info",
		"-s", h.storePath, "-d", h.haulerdir, "-o", "json")
	if exit != 0 {
		return fmt.Errorf("hauler store info -o json: %s", out)
	}
	var info struct {
		Artifacts []storeArtifact `json:"artifacts"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return fmt.Errorf("parsing store info JSON: %w", err)
	}

	// (a) image digest set: exactly the expected (lock ∩ platforms), no extras.
	storeImages := map[string]bool{}
	for _, a := range info.Artifacts {
		if a.Type == "image" {
			storeImages[a.Digest] = true
		}
	}
	expected := h.expectedDigests()
	problems := []string{}
	for dg := range expected {
		if !storeImages[dg] {
			problems = append(problems, "missing from store: "+dg)
		}
	}
	for dg := range storeImages {
		if _, ok := expected[dg]; !ok {
			problems = append(problems, "extra in store: "+dg)
		}
	}

	// (b) per image: platforms match; attestations + signatures are present in
	// the store AND byte-identical to the live referrer-tag manifests.
	for dg, repo := range expected {
		if !storeImages[dg] {
			continue
		}
		if plat := platformOf(info.Artifacts, dg); plat != "" && plat != "linux/amd64" {
			problems = append(problems, fmt.Sprintf("%s: platform %q unexpected", dg, plat))
		}
		for _, kind := range []string{"atts", "sigs"} {
			stored := findArtifact(info.Artifacts, dg, kind)
			if stored == "" {
				problems = append(problems, fmt.Sprintf("%s: no %s in store", dg, kind))
				continue
			}
			live, err := referrerTagDigest(h, repo, dg, kind)
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			if stored != live {
				problems = append(problems, fmt.Sprintf("%s %s: store=%s live=%s", dg, kind, stored, live))
			}
		}
	}

	charts := []storeArtifact{}
	for _, a := range info.Artifacts {
		if a.Type == "chart" {
			charts = append(charts, a)
		}
	}
	if len(charts) == 0 {
		problems = append(problems, "no chart artifact in store (kind=Charts doc was not hauled)")
	} else if len(charts) != 1 {
		problems = append(problems, fmt.Sprintf("expected exactly 1 chart artifact in store, got %d", len(charts)))
	} else if !strings.Contains(charts[0].Reference, h.l.Chart.Name) {
		problems = append(problems, fmt.Sprintf("chart artifact %q does not reference chart %s", charts[0].Reference, h.l.Chart.Name))
	}

	if len(problems) > 0 {
		return fmt.Errorf("parity problems: %s", strings.Join(problems, " | "))
	}
	h.ok(fmt.Sprintf("digest sets equal (%d images, no extras); chart %s hauled; platforms match; atts+sigs present and identical to live registry; store blob check passed", len(expected), h.l.Chart.Name))
	return nil
}

func platformOf(arts []storeArtifact, imageDigest string) string {
	for _, a := range arts {
		if a.Type == "image" && a.Digest == imageDigest {
			return a.Platform
		}
	}
	return ""
}

func findArtifact(arts []storeArtifact, imageDigest, kind string) string {
	for _, a := range arts {
		if a.Type == kind && strings.Contains(a.Reference, imageDigest) {
			return a.Digest
		}
	}
	return ""
}

// referrerTagDigest returns the sha256 of the manifest behind the cosign
// referrer tag (sha256-<digest>.att / .sig), proving store and registry carry
// identical bytes.
func referrerTagDigest(h *harness, repo, digest, kind string) (string, error) {
	suffix := map[string]string{"atts": ".att", "sigs": ".sig"}[kind]
	tag := fmt.Sprintf("%s:sha256-%s%s", repo, strings.TrimPrefix(digest, "sha256:"), suffix)
	c := exec.Command("crane", "manifest", tag)
	// crane needs the registry credentials written by `crane auth login`.
	c.Env = append(os.Environ(), "DOCKER_CONFIG="+h.dockerCfg)
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("crane manifest %s: %v", tag, err)
	}
	sum := sha256.Sum256(out)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// negative proves the verification machinery actually rejects bad input.
func (h *harness) negative() error {
	failures := []string{}

	// (1) tampered digest: converter accepts the well-formed lock, but sync
	// must abort because the digest no longer exists in the registry.
	last := h.l.Images[0].Digests[0].Digest
	tamperedDigit := "0"
	if strings.HasSuffix(last, "0") {
		tamperedDigit = "1"
	}
	tampered := strings.Replace(string(h.lockBytes), last, last[:len(last)-1]+tamperedDigit, 1)
	tamperedPath := filepath.Join(h.cfg.Workdir, "tampered.lock.yaml")
	tamperedManifest := filepath.Join(h.cfg.Workdir, "tampered.manifest.yaml")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o644); err != nil {
		return err
	}
	exit, out := h.cmdStdin("convert tampered lock (well-formed → conversion succeeds)", []byte(tampered), h.cfg.ConvertBin)
	if exit != 0 {
		failures = append(failures, "converter unexpectedly rejected the well-formed tampered lock: "+out)
	} else if err := os.WriteFile(tamperedManifest, []byte(out), 0o644); err != nil {
		return err
	}
	exit, out = h.cmd("sync tampered manifest (must abort)", "hauler", "store", "sync",
		"-f", tamperedManifest, "-k", h.pubKeyPath, "--use-tlog-verify",
		"-s", filepath.Join(h.cfg.Workdir, "store-neg1"), "-d", h.haulerdir, "--no-progress")
	if exit == 0 {
		failures = append(failures, "sync of tampered digest did NOT abort")
	}

	// (2) wrong key: signatures made with SUSE's key must fail verification.
	wrongKeyDir := filepath.Join(h.cfg.Workdir, "wrongkey")
	if err := os.MkdirAll(wrongKeyDir, 0o755); err != nil {
		return err
	}
	wrongKeyPrefix := filepath.Join(wrongKeyDir, "cosign")
	exit, out = h.cmd("generate throwaway keypair", "cosign", "generate-key-pair", "--output-key-prefix", wrongKeyPrefix)
	if exit != 0 {
		failures = append(failures, "cosign generate-key-pair failed: "+out)
	} else {
		exit, out = h.cmd("sync with wrong key (must abort)", "hauler", "store", "sync",
			"-f", h.manifestPath, "-k", wrongKeyPrefix+".pub", "--use-tlog-verify",
			"-s", filepath.Join(h.cfg.Workdir, "store-neg2"), "-d", h.haulerdir, "--no-progress")
		if exit == 0 {
			failures = append(failures, "sync with wrong key did NOT abort")
		}
		if !strings.Contains(out, "ignature verification") {
			failures = append(failures, "sync with wrong key failed for the wrong reason (no signature-verification error in output)")
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, " | "))
	}
	h.ok("tampered digest aborted sync; wrong cosign key aborted sync with a signature-verification error")
	return nil
}

// ----------------------------------------------------------------- docs ----

// writeEvidence writes evidence.json and EVIDENCE.md; returns the MD path.
func (h *harness) writeEvidence() string {
	b, _ := json.MarshalIndent(h.steps, "", "  ")
	_ = os.WriteFile(filepath.Join(h.cfg.Workdir, "evidence.json"), b, 0o644)

	var md strings.Builder
	md.WriteString("# E2E Evidence — imagelock2hauler\n\n")
	fmt.Fprintf(&md, "Lock: `%s`  \nsha256(lock): `%s`  \nPubkey: `%s`  \nPlatforms: %v\n\n",
		h.cfg.Lock, h.lockSHA, PubKeyURL, h.platforms)
	md.WriteString("## Success criteria\n\n")
	for _, line := range h.checklist() {
		md.WriteString("- " + line + "\n")
	}
	md.WriteString("\n## Steps\n\n")
	for _, s := range h.steps {
		status := "PASS"
		if !s.OK {
			status = "FAIL"
		}
		fmt.Fprintf(&md, "### %s — %s\n\n%s\n", s.Name, status, s.Detail)
		for _, c := range s.Cmds {
			fmt.Fprintf(&md, "\n```\n$ %s   # exit=%d — %s\n```\n", c.Cmd, c.Exit, c.Note)
		}
		md.WriteString("\n")
	}
	mdPath := filepath.Join(h.cfg.Workdir, "EVIDENCE.md")
	_ = os.WriteFile(mdPath, []byte(md.String()), 0o644)
	return mdPath
}

// checklist maps harness results
func (h *harness) checklist() []string {
	var lines []string
	add := func(done bool, text string) {
		mark := " "
		if done {
			mark = "x"
		}
		lines = append(lines, fmt.Sprintf("[%s] %s", mark, text))
	}
	add(h.stepOK("5-parity"), "digest set in haul == lock digest set for the selected platforms, none extra (integrity)")
	add(h.stepOK("3-reference-flow") && h.stepOK("4-hauler-sync"), "cosign verification at sync time with SUSE pubkey + tlog (authenticity)")
	add(h.stepOK("5-parity"), "attestations/signatures present in store and byte-identical to registry (supply-chain parity)")
	add(h.stepOK("6-negative"), "tampered digest and wrong key both abort (verification enforced)")
	return lines
}

func (h *harness) stepOK(name string) bool {
	for _, s := range h.steps {
		if s.Name == name {
			return s.OK
		}
	}
	return false
}

func readSource(source string) ([]byte, error) {
	if strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("fetching %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching %s: HTTP %d", source, resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(source)
}

func download(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}
