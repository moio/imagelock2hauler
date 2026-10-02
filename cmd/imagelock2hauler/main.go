// Command imagelock2hauler converts a SUSE Application Collection ImagesLock file
// into a Hauler manifest, preserving integrity (digest pinning) and
// authenticity (cosign key + tlog verification at sync time).
//
// The lock is read from stdin, the manifest is written to stdout:
//
//	curl -sf <lock-url> | imagelock2hauler [--platform x86_64,arm64] [--pin=tag]
//
// See README.md for the guarantees and the fixed assumptions (pubkey, tlog,
// chart manifest are always on; parsing is always strict).
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"imagelock2hauler/internal/lock"
	"imagelock2hauler/internal/manifest"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("imagelock2hauler", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var (
		platforms = fs.String("platform", "x86_64", "comma-separated platforms to include (x86_64, arm64, or os/arch)")
		pin       = fs.String("pin", "digest", "pin images by \"digest\" (default) or \"tag\" (degrades integrity; discouraged)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("unexpected arguments %v — the lock is read from stdin", fs.Args())
	}
	if *pin != "digest" && *pin != "tag" {
		return fmt.Errorf("--pin must be \"digest\" or \"tag\", got %q", *pin)
	}
	canon, err := manifest.NormalizePlatforms(splitCSV(*platforms))
	if err != nil {
		return err
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading lock from stdin: %w", err)
	}
	lockSum := sha256.Sum256(data) // the lock is unsigned; its hash is the audit anchor
	fmt.Fprintf(os.Stderr, "sha256(lock) = %x\n", lockSum)

	l, err := lock.Parse(data)
	if err != nil {
		return err
	}

	docs, err := manifest.Build(l, manifest.Options{
		Name:      manifest.StoreName(l, lockSum),
		Platforms: canon,
		PinTag:    *pin == "tag",
	})
	if err != nil {
		return err
	}

	manifestYAML, err := manifest.Emit(docs)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(manifestYAML)
	return err
}

const usage = `usage: imagelock2hauler [--platform list] [--pin digest|tag] < lock.yaml > manifest.yaml

Converts an AppCo ImagesLock (stdin) into a Hauler manifest (stdout).
Prints sha256(lock) to stderr for audit records.

flags:
  --platform list   comma-separated platforms to include (x86_64, arm64, os/arch);
                    default x86_64. Non-matching digests are omitted.
  --pin digest|tag  digest (default) or tag pinning
`

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
