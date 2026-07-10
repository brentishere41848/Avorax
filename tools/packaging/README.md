# Avorax Packaging Tools

These dependency-free Python tools provide common release checks for native
desktop packages.

- `package_manifest.py create` writes a bounded SHA-256 manifest for a staged
  Linux or macOS application bundle.
- `package_manifest.py verify` rejects missing, changed, unlisted, linked, or
  special files in that bundle.
- `smoke_local_core.py` loads the packaged Avorax Native Engine and verifies
  health, detect-only scanning, confirmed-only quarantine, listing, and restore
  with harmless exact-hash fixture bytes.
- `create_release_checksums.py` creates the deterministic consolidated
  `SHA256SUMS.txt` file from final installer artifacts and the lockfile SBOM.
- `create_dependency_sbom.py` creates a deterministic CycloneDX 1.6 component
  inventory from bounded Cargo, pub, and Python lockfile reads. It preserves
  package hashes where lockfiles provide them and explicitly reports partial
  license review and incomplete final-binary resolution; it is not represented
  as a complete production SBOM.

The smoke never writes EICAR, downloads malware, changes machine-wide settings,
or claims GUI, service, driver, or pre-execution proof.
