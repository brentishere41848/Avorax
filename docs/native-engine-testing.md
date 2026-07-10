# Native Engine Testing

Run ANE tests:

```powershell
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
```

Run local-core integration tests:

```powershell
cargo test --manifest-path core/zentor_local_core/Cargo.toml
```

Run Guard integration tests:

```powershell
cargo test --manifest-path core/zentor_guard_service/Cargo.toml
```

Run the ANE release gate:

```powershell
tools/zne/zne-release-gate.ps1 -CargoPath C:\path\to\cargo.exe
```

The ZNE and real-world coverage gates intentionally refuse ambient `cargo` lookup. Set `CARGO` or pass `-CargoPath` with an absolute local Cargo executable.

EICAR is used only as a safe anti-malware test. Real malware samples are not included.
