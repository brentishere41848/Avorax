# macOS Packaging

Build on native Apple Silicon or Intel macOS:

```bash
bash installer/macos/build-macos.sh --version 0.1.15
```

Outputs one architecture-specific disk image:

- `dist/Avorax-AntiVirus-0.1.15-macos-arm64.dmg`, or
- `dist/Avorax-AntiVirus-0.1.15-macos-x64.dmg`.

The builder compiles the Flutter app and Rust Core/Guard helpers, stages engine
assets inside the app, applies an ad-hoc code signature, verifies that signature,
creates and mounts the DMG, verifies the bounded package manifest, and runs the
harmless scan/quarantine/restore smoke from both the app and mounted image.

Ad-hoc signing is integrity evidence only. It does not authenticate Avorax as an
Apple Developer ID publisher, satisfy Gatekeeper distribution policy, or prove
Apple notarization.
