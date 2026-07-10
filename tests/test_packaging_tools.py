import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "packaging" / "package_manifest.py"
SPEC = importlib.util.spec_from_file_location("avorax_package_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
package_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_manifest)

CHECKSUM_MODULE_PATH = (
    ROOT / "tools" / "packaging" / "create_release_checksums.py"
)
CHECKSUM_SPEC = importlib.util.spec_from_file_location(
    "avorax_release_checksums", CHECKSUM_MODULE_PATH
)
assert CHECKSUM_SPEC is not None and CHECKSUM_SPEC.loader is not None
release_checksums = importlib.util.module_from_spec(CHECKSUM_SPEC)
CHECKSUM_SPEC.loader.exec_module(release_checksums)

SBOM_MODULE_PATH = ROOT / "tools" / "packaging" / "create_dependency_sbom.py"
SBOM_SPEC = importlib.util.spec_from_file_location(
    "avorax_dependency_sbom", SBOM_MODULE_PATH
)
assert SBOM_SPEC is not None and SBOM_SPEC.loader is not None
dependency_sbom = importlib.util.module_from_spec(SBOM_SPEC)
SBOM_SPEC.loader.exec_module(dependency_sbom)


class PackageManifestTests(unittest.TestCase):
    def test_create_and_verify_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "engine" / "rules").mkdir(parents=True)
            (root / "Avorax").write_bytes(b"app")
            (root / "engine" / "rules" / "core.arule").write_bytes(b"rule")
            created = package_manifest.create_manifest(
                root, "0.1.15", "linux-x64", "unsigned"
            )
            verified = package_manifest.verify_manifest(root)
            self.assertEqual(created["file_count"], 2)
            self.assertEqual(verified["verified_files"], 2)
            self.assertEqual(verified["status"], "passed")

    def test_verify_rejects_tampered_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "Avorax"
            payload.write_bytes(b"before")
            package_manifest.create_manifest(root, "0.1.15", "linux-x64", "unsigned")
            payload.write_bytes(b"after")
            with self.assertRaisesRegex(package_manifest.ManifestError, "mismatch"):
                package_manifest.verify_manifest(root)

    def test_verify_rejects_unlisted_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Avorax").write_bytes(b"app")
            package_manifest.create_manifest(root, "0.1.15", "linux-x64", "unsigned")
            (root / "late-file").write_bytes(b"late")
            with self.assertRaisesRegex(package_manifest.ManifestError, "file set mismatch"):
                package_manifest.verify_manifest(root)

    def test_manifest_rejects_parent_traversal_row(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Avorax").write_bytes(b"app")
            package_manifest.create_manifest(root, "0.1.15", "linux-x64", "unsigned")
            manifest_path = root / package_manifest.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["path"] = "../outside"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(package_manifest.ManifestError, "unsafe"):
                package_manifest.verify_manifest(root)

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires optional privileges")
    def test_create_and_verify_safe_internal_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Versions" / "A").mkdir(parents=True)
            (root / "Versions" / "Current").symlink_to("A", target_is_directory=True)
            created = package_manifest.create_manifest(
                root, "0.1.15", "macos-arm64", "ad-hoc"
            )
            verified = package_manifest.verify_manifest(root)
            self.assertEqual(created["files"][0]["type"], "symlink")
            self.assertEqual(verified["verified_files"], 1)

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires optional privileges")
    def test_create_rejects_external_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "linked").symlink_to("/Applications")
            with self.assertRaisesRegex(package_manifest.ManifestError, "relative"):
                package_manifest.create_manifest(
                    root, "0.1.15", "macos-arm64", "ad-hoc"
                )

    def test_create_rejects_invalid_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(package_manifest.ManifestError, "version"):
                package_manifest.create_manifest(
                    Path(temporary), "../../bad", "linux-x64", "unsigned"
                )


class ReleaseChecksumTests(unittest.TestCase):
    def test_release_checksums_are_sorted_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "b.dmg").write_bytes(b"mac")
            (root / "a.msi").write_bytes(b"windows")
            (root / "Avorax-lockfile.cdx.json").write_bytes(b"sbom")
            output = root / "SHA256SUMS.txt"
            rows = release_checksums.create_checksums(root, output)
            self.assertEqual(
                [name for name, _ in rows],
                ["Avorax-lockfile.cdx.json", "a.msi", "b.dmg"],
            )
            self.assertEqual(
                output.read_text(encoding="ascii").splitlines(),
                [f"{digest}  {name}" for name, digest in rows],
            )

    def test_release_checksums_reject_duplicate_basenames(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").mkdir()
            (root / "two").mkdir()
            (root / "one" / "same.exe").write_bytes(b"one")
            (root / "two" / "same.exe").write_bytes(b"two")
            with self.assertRaisesRegex(release_checksums.ChecksumError, "unique"):
                release_checksums.create_checksums(
                    root, root / "SHA256SUMS.txt"
                )


class DependencySbomTests(unittest.TestCase):
    @staticmethod
    def _write_fixture_locks(root: Path) -> tuple[Path, Path, Path, Path]:
        cargo_one = root / "Cargo.lock"
        cargo_one.write_text(
            'version = 4\n\n[[package]]\nname = "alpha"\nversion = "1.2.3"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{"a" * 64}"\n',
            encoding="utf-8",
        )
        cargo_two = root / "other-Cargo.lock"
        cargo_two.write_text(cargo_one.read_text(encoding="utf-8"), encoding="utf-8")
        pub = root / "pubspec.lock"
        pub.write_text(
            "# Generated by pub\n"
            "packages:\n"
            "  args:\n"
            "    dependency: \"direct main\"\n"
            "    description:\n"
            "      name: args\n"
            f"      sha256: {'b' * 64}\n"
            "      url: \"https://pub.dev\"\n"
            "    source: hosted\n"
            "    version: \"2.7.0\"\n"
            "  flutter:\n"
            "    dependency: transitive\n"
            "    description: flutter\n"
            "    source: sdk\n"
            "    version: \"0.0.0\"\n"
            "sdks:\n"
            "  dart: \">=3.12.0 <4.0.0\"\n",
            encoding="utf-8",
        )
        requirements = root / "requirements.lock.txt"
        requirements.write_text("Example_Package==4.5.6\n", encoding="utf-8")
        return cargo_one, cargo_two, pub, requirements

    def test_lockfile_bom_is_deterministic_deduplicated_and_honest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo_one, cargo_two, pub, requirements = self._write_fixture_locks(root)
            first = dependency_sbom.create_bom(
                version="0.1.15",
                cargo_locks=[cargo_one, cargo_two],
                pub_locks=[pub],
                requirements_locks=[requirements],
                root=root,
            )
            second = dependency_sbom.create_bom(
                version="0.1.15",
                cargo_locks=[cargo_one, cargo_two],
                pub_locks=[pub],
                requirements_locks=[requirements],
                root=root,
            )

            self.assertEqual(first, second)
            self.assertEqual(
                first["$schema"],
                "https://cyclonedx.org/schema/bom-1.6.schema.json",
            )
            self.assertEqual(first["bomFormat"], "CycloneDX")
            self.assertEqual(first["specVersion"], "1.6")
            self.assertEqual(len(first["components"]), 4)
            metadata = {
                item["name"]: item["value"]
                for item in first["metadata"]["properties"]
            }
            self.assertEqual(metadata["avorax:license-review-status"], "partial")
            self.assertEqual(metadata["avorax:final-binary-resolution"], "false")
            self.assertEqual(first["compositions"][0]["aggregate"], "incomplete")
            alpha = next(item for item in first["components"] if item["name"] == "alpha")
            origins = next(
                item["value"]
                for item in alpha["properties"]
                if item["name"] == "avorax:lockfiles"
            )
            self.assertIn(cargo_one.as_posix(), origins)
            self.assertIn(cargo_two.as_posix(), origins)
            self.assertEqual(alpha["hashes"][0]["content"], "a" * 64)

    def test_pub_hosted_package_without_sha256_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, pub, _ = self._write_fixture_locks(root)
            pub.write_text(
                pub.read_text(encoding="utf-8").replace(
                    f"      sha256: {'b' * 64}\n", ""
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                dependency_sbom.SbomError, "lacks pub.dev SHA-256 evidence"
            ):
                dependency_sbom.add_pub_lock({}, pub, root)

    def test_pub_duplicate_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, pub, _ = self._write_fixture_locks(root)
            pub.write_text(
                pub.read_text(encoding="utf-8").replace(
                    "    source: hosted\n", "    source: hosted\n    source: hosted\n"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(dependency_sbom.SbomError, "duplicate"):
                dependency_sbom.add_pub_lock({}, pub, root)

    def test_sbom_atomic_writer_rejects_link_output(self):
        if os.name == "nt":
            self.skipTest("Windows symlink creation requires optional privileges")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            linked = root / "linked.cdx.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(dependency_sbom.SbomError, "regular file"):
                dependency_sbom._write_atomic(
                    linked, {"bomFormat": "CycloneDX"}, root
                )

    def test_lockfile_outside_explicit_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            trusted = parent / "trusted"
            trusted.mkdir()
            outside = parent / "outside-requirements.txt"
            outside.write_text("example==1.0.0\n", encoding="utf-8")
            with self.assertRaisesRegex(dependency_sbom.SbomError, "outside"):
                dependency_sbom.add_requirements_lock({}, outside, trusted)


class DesktopPackageWorkflowTests(unittest.TestCase):
    def test_workflow_creates_hashes_and_publishes_partial_lockfile_sbom(self):
        workflow = (ROOT / ".github" / "workflows" / "desktop-packages.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("tools/packaging/create_dependency_sbom.py", workflow)
        self.assertIn("--repo-root .", workflow)
        self.assertIn("--cargo-lock Cargo.lock", workflow)
        self.assertIn("--pub-lock apps/zentor_client/pubspec.lock", workflow)
        self.assertIn("--requirements-lock ml/requirements.lock.txt", workflow)
        self.assertIn("-lockfile.cdx.json", workflow)
        self.assertGreaterEqual(workflow.count("release-assets/*.cdx.json"), 2)
        self.assertIn("partial dependency inventory", workflow)
        self.assertIn("not a complete license review", workflow)

    def test_workflow_actions_are_exact_node24_compatible_pins(self):
        workflows = {
            path.name: path.read_text(encoding="utf-8")
            for path in (ROOT / ".github" / "workflows").glob("*.yml")
        }
        combined = "\n".join(workflows.values())

        expected_pins = {
            "actions/checkout": "93cb6efe18208431cddfb8368fd83d5badbf9bfd",
            "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
            "actions/setup-dotnet": "26b0ec14cb23fa6904739307f278c14f94c95bf1",
            "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            "dtolnay/rust-toolchain": "fa04a1451ff1842e2626ccb99004d0195b455a88",
            "subosito/flutter-action": "1a449444c387b1966244ae4d4f8c696479add0b2",
            "softprops/action-gh-release": "718ea10b132b3b2eba29c1007bb80653f286566b",
        }
        for action, commit in expected_pins.items():
            self.assertIn(f"uses: {action}@{commit}", combined)

        mutable_ref = re.compile(
            r"^\s*uses:\s+(?!\./)([^\s@]+)@(?![0-9a-f]{40}(?:\s|$))",
            re.MULTILINE,
        )
        self.assertEqual(mutable_ref.findall(combined), [])

        rust_action = (
            "uses: dtolnay/rust-toolchain@"
            "fa04a1451ff1842e2626ccb99004d0195b455a88"
        )
        for name, workflow in workflows.items():
            lines = workflow.splitlines()
            for index, line in enumerate(lines):
                if rust_action not in line:
                    continue
                context = "\n".join(lines[index + 1:index + 4])
                self.assertIn("with:", context, name)
                self.assertRegex(context, r"toolchain:\s+(?:1\.96\.1|\$\{\{ env\.RUST_TOOLCHAIN \}\})", name)

    def test_msi_admin_extract_waits_for_real_exit_code(self):
        workflow = (ROOT / ".github" / "workflows" / "desktop-packages.yml").read_text(
            encoding="utf-8"
        )
        _, extraction_step = workflow.split(
            "- name: Administratively extract MSI without installing", maxsplit=1
        )
        extraction_step, _ = extraction_step.split(
            "- name: Record unsigned status and checksums", maxsplit=1
        )
        msiexec_section, _ = extraction_step.split("$apps = @(", maxsplit=1)

        self.assertIn("$process = Start-Process", msiexec_section)
        self.assertIn("-Wait", msiexec_section)
        self.assertIn("-PassThru", msiexec_section)
        self.assertIn("-WindowStyle Hidden", msiexec_section)
        self.assertIn("$process.ExitCode", msiexec_section)
        self.assertNotIn("$LASTEXITCODE", msiexec_section)

    def test_linux_tarball_is_extracted_and_smoked(self):
        builder = (ROOT / "installer" / "linux" / "build-linux.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('TAR_EXTRACT_ROOT="$DIST_ROOT/tar-extracted"', builder)
        self.assertIn('tar -xzf "$TARBALL" --no-same-owner --no-same-permissions', builder)
        self.assertIn('--root "$TAR_EXTRACT_ROOT/Avorax"', builder)
        self.assertIn('--core "$TAR_EXTRACT_ROOT/Avorax/avorax_core_service"', builder)
        self.assertIn('--report "$VERIFY_ROOT/linux-tar-core-smoke.json"', builder)

    def test_package_smoke_canonicalizes_its_owned_temporary_root(self):
        smoke = (ROOT / "tools" / "packaging" / "smoke_local_core.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("root = Path(temporary).resolve(strict=True)", smoke)

    def test_macos_dmg_verify_retries_only_transient_resource_busy_errors(self):
        builder = (ROOT / "installer" / "macos" / "build-macos.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("verify_dmg()", builder)
        self.assertIn("for attempt in 1 2 3", builder)
        self.assertIn('output="$(hdiutil verify "$DMG" 2>&1)"', builder)
        self.assertIn('"$output" != *"Resource temporarily unavailable"*', builder)
        self.assertIn('return "$status"', builder)
        self.assertIn('sleep "$((attempt * 2))"', builder)

    def test_native_builders_handle_tool_absence_without_swallowing_errors(self):
        for platform in ("linux", "macos"):
            builder = (
                ROOT / "installer" / platform / f"build-{platform}.sh"
            ).read_text(encoding="utf-8")

            self.assertIn('if ! candidate="$(command -v "$fallback")"; then', builder)
            self.assertIn('candidate=""', builder)
            self.assertNotIn("|| true", builder)

    def test_macos_entitlement_and_mount_cleanup_fail_visibly(self):
        builder = (ROOT / "installer" / "macos" / "build-macos.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('if ! codesign -d --entitlements :- "$APP"', builder)
        self.assertIn("refusing to package without sandbox evidence", builder)
        self.assertIn("local prior_status=$?", builder)
        self.assertIn("Failed to detach the Avorax DMG mount during cleanup", builder)
        self.assertIn('return "$prior_status"', builder)


if __name__ == "__main__":
    unittest.main()
