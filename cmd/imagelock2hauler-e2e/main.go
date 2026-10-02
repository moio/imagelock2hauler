// Command imagelock2hauler-e2e runs the automated end-to-end verification
// against a live AppCo lock and writes evidence to the workdir.
//
// Usage:
//
//	imagelock2hauler-e2e --lock <url|file> --workdir /tmp/e2e
//
// Reads APPCO_USER / APPCO_TOKEN from the environment. Requires crane,
// cosign and hauler on PATH.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"imagelock2hauler/internal/harness"
)

func main() {
	fs := flag.NewFlagSet("imagelock2hauler-e2e", flag.ContinueOnError)
	var (
		lock     = fs.String("lock", "", "ImagesLock https URL or local file (required)")
		workdir  = fs.String("workdir", "/tmp/imagelock2hauler-e2e", "fresh working directory for store + evidence")
		registry = fs.String("registry", "dp.apps.rancher.io", "registry to authenticate against")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *lock == "" {
		fs.Usage()
		os.Exit(2)
	}
	user, token := os.Getenv("APPCO_USER"), os.Getenv("APPCO_TOKEN")
	if user == "" || token == "" {
		fmt.Fprintln(os.Stderr, "error: APPCO_USER and APPCO_TOKEN must be set")
		os.Exit(2)
	}
	convertBin, err := converterBinary()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	workDir, err := filepath.Abs(*workdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	err = harness.Run(harness.Config{
		Lock:       *lock,
		Workdir:    workDir,
		ConvertBin: convertBin,
		Registry:   *registry,
		User:       user,
		Token:      token,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "E2E FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("E2E PASSED")
}

// converterBinary locates the imagelock2hauler CLI: next to this binary, or on
// PATH. The harness runs it once so the CLI itself stays honest.
func converterBinary() (string, error) {
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), "imagelock2hauler")
		if _, err := os.Stat(sibling); err == nil {
			return sibling, nil
		}
	}
	if p, err := exec.LookPath("imagelock2hauler"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("imagelock2hauler CLI not found next to the harness or on PATH")
}
