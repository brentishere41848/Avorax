# Linux Packaging

Build on native x86-64 Linux:

```bash
bash installer/linux/build-linux.sh --version 0.1.15
```

Outputs:

- `dist/Avorax-AntiVirus-0.1.15-linux-x64.deb`
- `dist/Avorax-AntiVirus-0.1.15-linux-x64.tar.gz`
- `dist/SHA256SUMS-linux.txt`

The builder compiles the Flutter app and Rust Core/Guard helpers, stages engine
assets, creates and verifies a bounded integrity manifest, runs the harmless
scan/quarantine/restore smoke, builds the packages, extracts the DEB without
installing it, and repeats manifest and core verification. It does not install a
system service, kernel module, startup entry, or privileged helper.
