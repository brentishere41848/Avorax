# Avorax Portable Scanner Beta 0.1.0-beta.1

## Beta Safety Disclaimer

Avorax Portable Scanner Beta is experimental, limited security software. Do
not rely on it as your only antivirus. It can manually scan common local
threats covered by the bundled signatures, rules, static analysis, and
conservative heuristics, but it may fail to detect or stop advanced, novel,
targeted, polymorphic, fileless, kernel-level, or large-scale malware and
ransomware attacks. Keep Microsoft Defender or another supported, up-to-date
antivirus enabled. No antivirus can guarantee detection of every threat.

## Available Asset

- `Avorax-Portable-Beta-0.1.0-beta.1.zip`: verified Windows x64 portable bundle.
- SHA-256: `a80155373a869576dad6d015c21221a18815bf3318a253a11c19477af128240b`.

Extract the ZIP, run `Avorax-Status.cmd`, and only continue when it reports the
engine as ready. Then run `Avorax-Quick-Scan.cmd` for a detect-only manual scan.
Runtime data is stored below `%LOCALAPPDATA%\Avorax\PortableBeta`.

## Verified Scope

- Canonical Windows local-core executable and bundled native engine assets.
- Ready health with local stdio IPC and no exposed network listener.
- Thirteen local signatures, nine local rules, and native self-test success.
- Manual Quick, Full, File, and Folder scan command paths.
- Quarantine list, integrity-checked restore, rescan, and confirmed deletion.
- Allowlist list/add/remove command paths with explicit mutation confirmation.
- Bounded ZIP extraction, per-file manifest hashes, and adversarial archive
  rejection for traversal, case-insensitive duplicates, compression ratio, and
  manifest tampering.

## Not Included

- No MSI installer or packaged Windows GUI is published in this beta because
  those artifacts cannot be built and verified on the current host without a
  .NET SDK, Visual Studio Desktop C++ components, and Windows symlink support.
- No standalone launcher EXE is published. The bundled
  `zentor_local_core.exe` is an internal command engine and must remain with its
  verified scripts and engine assets inside the ZIP.
- No Linux build is published because a native Linux/Flutter build and runtime
  verification have not been performed on a Linux release host.
- No service, startup persistence, scheduled background task, signed driver,
  persistent monitoring, Microsoft Defender replacement, or guaranteed
  before-execution blocking.
- The ZIP is not code-signed and is not a production release.

Publishing an unbuilt or untested MSI, standalone EXE, or Linux binary under
these names would create false-success artifacts and is intentionally refused.
