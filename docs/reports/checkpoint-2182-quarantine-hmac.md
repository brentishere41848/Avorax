# Checkpoint 2182 Quarantine Metadata Authentication

Date: 2026-08-19

## Finding

Local Core and Guard Service stored quarantine metadata authentication as a
custom prefix-keyed SHA-256 construction. Local Core also accepted a JSON record
when its auth sidecar was absent. In addition, the two writers used different
authentication domains even though they target the same quarantine directory,
and Local Core rejected Guard-specific source/action evidence. A Guard-created
record could therefore fail to appear in the normal list/restore path.

This was an integrity and interoperability defect. It did not bypass payload
hash verification or make an unknown file a confirmed detection, but a local
actor able to modify quarantine metadata could remove authentication evidence,
and legitimate Guard records could become unavailable to the operator.

## Repair

- New Local Core and Guard records use the shared domain-separated
  `hmac-sha256:` format backed by the RustCrypto `hmac` crate and SHA-256.
- New keys contain 32 bytes from the operating-system random source through
  `getrandom` and are stored as lowercase hexadecimal before protection.
- Windows accepts only `dpapi:` key material. Plaintext Windows key files fail
  closed; DPAPI output is checked not to contain the clear fixture key.
- Missing auth sidecars now fail visibly. Unsigned legacy records are disabled.
- Local Core recognizes exact valid v1 Local Core and Guard tags only for a
  controlled migration. Migration occurs after strict JSON, ID, filename,
  path, hash, field, source, action, and execution-evidence validation, then
  re-reads and verifies the unchanged record with the v2 HMAC.
- Unknown JSON fields are rejected. A metadata filename must match its embedded
  quarantine ID.
- Local Core validates the two real Guard quarantine actions and can list and
  restore a Guard record while preserving historical process evidence.
- Guard's focused quarantine filter now includes its auth-key, legacy, DPAPI,
  schema, and shared-contract regressions by name.

No live malware, standard EICAR string, Defender exclusion, machine-wide
installation, service change, driver action, or broad filesystem deletion was
used. Tests write only benign bytes below isolated temporary directories.

## Dependency Review

`hmac` `0.12.1` and `getrandom` `0.3.4` were already present in the workspace
lockfile through transitive dependencies. They are now direct dependencies of
Local Core and Guard so the security contract is explicit. Their locally cached
crate metadata reports `MIT OR Apache-2.0`. `Cargo.lock` remains Cargo-generated.

## Verification

```powershell
cargo test --manifest-path core\zentor_local_core\Cargo.toml quarantine -- --test-threads=1
# 108 passed; 0 failed

cargo test --manifest-path core\zentor_guard_service\Cargo.toml quarantine -- --test-threads=1
# 42 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml -- --test-threads=1
# 515 passed; 0 failed

cargo test --manifest-path core\zentor_guard_service\Cargo.toml -- --test-threads=1
# 219 passed; 0 failed

cargo test --workspace --all-targets --quiet -- --test-threads=1
# 1,422 passed across the workspace; 0 failed

flutter test --reporter compact
# 838 passed; 0 failed
```

Additional local gates passed: `cargo fmt --all -- --check`, strict Clippy for
Local Core and Guard with `-D warnings`, `618` Python source contracts, dependency
and license evidence, PowerShell parsing, `git diff --check`, and
`cargo build --workspace --release`.

The full central verifier passed `217/217` steps with no failed or skipped steps
in `935.8s`. Its independent `-RequireFullSuite` report validator passed in
`2.3s`. The structured report is
`.verification/2182-small-threat-mvp-report.json`; that local evidence directory
is intentionally not committed. Branch CI and package CI remain pending until
the reviewed checkpoint is pushed.

## Classification

- **Verified locally:** shared HMAC format, 32-byte OS-random keys, Windows
  DPAPI-only decode, tamper rejection, unsigned rejection, strict schema,
  filename/ID binding, valid v1 migration, invalid-record non-migration, and
  Guard record list/restore interoperability in isolated runtime tests.
- **Partial:** installed Core/Guard/UI use of the LocalSystem-owned shared key,
  installed quarantine ACLs, DPAPI upgrade/recovery, service mutation IPC, and
  packaged UI click-through.
- **Blocked:** production signer/key custody and disposable elevated Windows
  install/repair/uninstall E2E are not available in this checkout.
- **Technically limited:** HMAC authenticates metadata but does not encrypt the
  payload, permanent deletion is not secure erase, and this change does not add
  pre-execution or kernel blocking.
