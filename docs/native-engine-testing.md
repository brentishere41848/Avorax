# Native Engine Testing

Run PNE tests:

```powershell
cargo test --manifest-path core/pasus_native_engine/Cargo.toml
```

Run local-core integration tests:

```powershell
cargo test --manifest-path core/pasus_local_core/Cargo.toml
```

Run Guard integration tests:

```powershell
cargo test --manifest-path core/pasus_guard_service/Cargo.toml
```

Run the PNE release gate:

```powershell
tools/pne/pne-release-gate.ps1
```

EICAR is used only as a safe anti-malware test. Real malware samples are not included.
