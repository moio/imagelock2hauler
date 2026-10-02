# imagelock2hauler

Converts a SUSE Application Collection (AppCo) `ImagesLock` file into a 
[Hauler](https://docs.hauler.dev) manifest that preserves the release's
integrity and authenticity guarantees.


## Converter

The lock is read from **stdin**, the manifest is written to **stdout**:

```bash
go build ./cmd/imagelock2hauler
curl -sf <lock-url> | ./imagelock2hauler [--platform x86_64,arm64] [--pin=tag]
```

Example:

```bash
curl -sf https://apps.rancher.io/artifacts/f0124041d528d5e22c30390c53dfaf63f41168a368f22a8e049df04f5dddc14d/resources/fluent-bit-0.58.2-27.1.images-lock.yaml | ./imagelock2hauler


curl -sf https://apps.rancher.io/artifacts/8d8be818bdedb4ec83fbe220d8fc2f1d1d3843fffa8cad8fc1b82f4ea6d73f63/resources/alertmanager-2.0.1-85.1.images-lock.yaml | ./imagelock2hauler
```
Flags:

| flag | meaning |
|---|---|
| `--platform` | comma-separated platforms to include (`x86_64`, `arm64`, or `os/arch`); default **x86_64**. Sets `hauler.dev/platform` and omits non-matching digests. |
| `--pin` | `digest` (default) or `tag` (degrades integrity; discouraged) |

Assumptions:

- verification key is always `https://apps.rancher.io/ap-pubkey.pem`
- tlog verification always enabled (`hauler.dev/use-tlog-verify: "true"`)
- a `Charts` doc is always emitted for the chart itself (tag-pinned — the lock
  has no chart digest; authenticity still enforced by cosign key verification)
- parsing is always strict: unknown lock fields fail loudly (no
  `--allow-unknown`), so schema drift can never silently lose digests
- validation also fails loudly on wrong `apiVersion`/`kind`, malformed image
  refs, bad digest shape, and empty `digests`

## Why this is safe

An AppCo lock pins the **per-architecture manifest digest** of every image.
The converter emits one **digest-pinned** Hauler entry per (image, arch), so
pulling is content-addressed — hauler cannot store anything but the exact
bytes the lock describes. Authenticity is preserved by making hauler run the
same cryptographic check AppCo documents: cosign verification with SUSE's
public key + Rekor transparency log, at sync time (`hauler.dev/key` +
`hauler.dev/use-tlog-verify: "true"`). Signatures, attestations, SBOMs and
referrers are hauled by default.

Things the converter deliberately never emits: `rewrite` (severs
digest-to-lock correspondence), tag-based refs (unless `--pin=tag`), keyless/
OIDC fields, `--ignore-errors`.

## E2E test

`imagelock2hauler-e2e` runs the full manual verification and records evidence:

```bash
export APPCO_USER=… APPCO_TOKEN=…          # AppCo service-account credentials

go build ./cmd/imagelock2hauler-e2e
./imagelock2hauler-e2e \
  --lock https://apps.rancher.io/artifacts/8d8be818bdedb4ec83fbe220d8fc2f1d1d3843fffa8cad8fc1b82f4ea6d73f63/resources/alertmanager-2.0.1-85.1.images-lock.yaml \
  --workdir /tmp/e2e
```

Requires crane cosign and hauler on PATH.
