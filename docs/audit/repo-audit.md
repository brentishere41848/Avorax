# Avorax Repository Audit

Date: 2026-05-30

## Scope

This audit covers active Avorax Anti-Virus repository content: Flutter desktop client, Rust engine and services, native assets, Windows validation paths, installer tooling, CI workflows, documentation, and release gates. It excludes `archive/` from active product decisions except when checking that archived material is not referenced by active builds.

## Findings

- Active product naming is Avorax Anti-Virus, with Avorax Native Engine (ANE), Avorax Core Service, and Avorax Guard Service as the product/service language.
- The repository contains a Flutter client under `apps/zentor_client/`, Rust crates under `core/` and `services/api/`, native assets under `assets/zentor_native/`, tools under `tools/`, installer scripts under `installer/windows/`, and CI workflows under `.github/workflows/`.
- Legacy website material is archived under `archive/` and should not be restored into active builds.
- Branding/product gates exist and have been strengthened to scan active product-facing paths for legacy naming, unrelated product-domain wording, and fake protection claims.
- A repository-level Rust workspace now exists so the documented baseline command `cargo test --workspace` has a real workspace entry point.
- Windows driver validation remains blocked in this environment and must not be marketed as active pre-execution protection.
- Native ML remains development/supportive unless production-ready metadata and validation gates prove otherwise.

## Baseline Commands

Commands attempted or prepared for this audit:

```bash
cargo test --workspace
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
./tools/branding/branding-check.sh
# plus the product-copy gate fake-claim phrase set in tools/security/zentor-product-copy-gate.ps1
```

Flutter, Dart, and PowerShell checks require the missing local tools documented in `docs/audit/known-blockers.md`.

## Phase 0 Result

Phase 0 remains partially complete until all baseline commands pass in a fully provisioned environment. The repository now has explicit active-component and blocker audit documents, a workspace-level Rust test entry point, and stricter product-copy gates for active product text.
