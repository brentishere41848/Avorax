# Checkpoint 2183 Native Engine Mutation Boundary

Date: 2026-08-19

## Finding

The Native Engine contained a second direct quarantine implementation alongside
the authenticated Local Core and Guard lifecycle. Its record format had no
metadata authentication sidecar, no Local Core restore path, and a different
ownership model. On Windows and Linux it could target the same configured
quarantine root as Local Core. A Native Engine auto-action could therefore move
a file into storage that the Recovery Vault could not safely authenticate or
manage.

The product scan path already called the Native Engine in `DetectOnly` mode and
then applied any confirmed quarantine through Local Core. The duplicate native
mutation path was unnecessary and unsafe to expose as a working control.

## Repair

- The Native Engine is now a detection and explainable-verdict component only.
- `scan_file`, byte self-test scans, and root scans reject both native
  auto-quarantine compatibility modes before reading a file or walking roots.
- `DetectOnly` and `LockdownReview` retain non-mutating detection behavior.
- The direct native `quarantine` entry point fails immediately with an explicit
  instruction to use the authenticated Local Core lifecycle.
- Native production code no longer constructs `QuarantineStore`, evaluates its
  old auto-action helper, or reads a file for direct quarantine.
- The old low-level native store, quarantine extension helper, and native
  auto-action policy are private test-only modules. They retain bounded
  regression coverage without remaining reachable product mutation paths.
- Serialized compatibility fields and action-mode variants remain stable, but
  their disabled behavior is documented in the Rust API.
- The central verifier and its independent report validator require the new
  `native-engine detection-only mutation boundary regressions` evidence.

Local Core quick, full, custom, watcher, and manual scans are unchanged. Local
Core still calls the Native Engine with `DetectOnly`, aggregates its verdict,
and owns authenticated quarantine, list, rescan, restore, and delete actions.

No dependency changed. No live malware, standard EICAR string, Defender
exclusion, service or driver operation, machine-wide installation, or project
file deletion was used. Runtime tests use benign bytes below isolated temporary
directories.

## Verification

```powershell
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_mutation_boundary -- --test-threads=1
# 3 passed; 0 failed

cargo test --manifest-path core\zentor_native_engine\Cargo.toml -- --test-threads=1
# 435 engine tests and 6 compiler tests passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml -- --test-threads=1
# 515 passed; 0 failed

cargo test --workspace --all-targets --quiet -- --test-threads=1
# 1,423 passed across the workspace; 0 failed

flutter test --reporter compact
# 838 passed; 0 failed

python -B tools\testing\run-python-source-contracts.py
# 619 passed; 0 failed

cargo clippy --manifest-path core\zentor_native_engine\Cargo.toml --all-targets --no-deps -- -D warnings
# passed with no warnings
```

Rust formatting, PowerShell parser checks, and `git diff --check` also pass. The
central verifier passed `218/218` steps with no failed or skipped steps in
`836.4s`; its independent `-RequireFullSuite` report validator passed in `1.9s`.
The structured report is `.verification/2183-small-threat-mvp-report.json` and
is intentionally not committed. Package and GitHub head evidence is recorded
after the final checkpoint review rather than inferred here.

## Classification

- **Verified locally:** mutating native scan modes fail before path I/O; direct
  native quarantine fails before path I/O; detect-only and lockdown review
  still return verdicts without mutation; production Native Engine code cannot
  construct its old store; Local Core remains the authenticated lifecycle owner.
- **Partial:** packaged UI click-through and installed Local Core/Guard service
  mediation still require a disposable elevated Windows host.
- **Disabled with blocker:** Native Engine direct and automatic quarantine are
  disabled because the duplicate unauthenticated record schema, DPAPI security
  context, and missing restore contract cannot safely interoperate with the
  Local Core vault. The supported path is Local Core quarantine.
- **Technically limited:** this is a user-mode ownership repair. It does not add
  kernel interception, pre-execution blocking, production signing, secure
  erase, or a production detection-rate claim.
