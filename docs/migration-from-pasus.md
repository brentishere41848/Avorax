# Migration From Pasus

Avorax was previously developed under the internal project name Pasus.

The active product name is now Avorax Anti-Virus, from Avorax Security. Active UI, services, installers, native engine assets, IPC names, release artifacts, and documentation should use Avorax naming.

The local core keeps a safe migration path for existing preview users:

- Detect the old Pasus local data directory.
- Copy config, quarantine metadata, allowlist data, logs, and scan history into the Avorax data directory.
- Preserve quarantine metadata and original paths.
- Keep old `.pasusq` quarantine files readable.
- Write new quarantine files as `.zentorq` for compatibility with existing preview tooling until the quarantine extension migration is implemented.
- Do not delete old data automatically.
- Do not restore or re-enable quarantined files during migration.

Migration writes an internal event after a successful copy: "Migrated local data from Pasus to Avorax".
