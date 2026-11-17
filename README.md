# OCULI intelligence publisher (GitHub Actions)

This repository builds and publishes the signed CVE snapshot that OCULI
endpoints download automatically. It contains only the snapshot builder
(`cmd/oculi-intel-builder`) and its `intel` package — not the OCULI app.

## One-time setup

1. Create a **public** GitHub repository (e.g. `oculi-intel`) and upload the
   contents of this folder (including `.github/workflows/publish.yml`).
   Public is required: endpoints download release files without a login.
   Only the signed snapshot is public; the signing key never leaves the
   repository secret.
2. Repository → Settings → Secrets and variables → Actions → **New repository
   secret**: name `OCULI_SIGNING_KEY`, value = the full content of the private
   key file (`oculi-test-2026-11.key`, kept offline in
   `OCULI\_PRIVATE-KEY-TEST-simpan-offline`).
3. Actions tab → *Publish OCULI intelligence* → **Run workflow** once. The
   first run takes about 5–10 minutes and creates a release with
   `manifest.json` and `oculi-intel.zip`.
4. Tell OCULI the update source (or have it compiled in as the default):
   `https://github.com/<owner>/oculi-intel/releases/latest/download/`

After that the workflow runs every day; OCULI checks every 6 hours, downloads
only the small manifest when nothing changed, verifies the Ed25519 signature
and SHA-256, and switches to the new snapshot (the previous one is kept for
rollback).

## Security notes

- Snapshots are signed with the key in `OCULI_SIGNING_KEY`; OCULI accepts only
  keys listed in its embedded `intel_keys.txt`. A compromised GitHub account
  cannot make OCULI accept data unless the private key is also stolen.
- The current key is the **TEST** key (`oculi-test-2026-11`), so snapshots are
  marked TEST. Before production, generate a production key offline
  (`oib keygen`), add its public key to OCULI, and replace the secret.
- The workflow passes `-test`; remove it in `publish.yml` only after
  switching to a production key.
