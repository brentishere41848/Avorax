import importlib.util
import json
import os
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
            output = root / "SHA256SUMS.txt"
            rows = release_checksums.create_checksums(root, output)
            self.assertEqual([name for name, _ in rows], ["a.msi", "b.dmg"])
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


class DesktopPackageWorkflowTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
