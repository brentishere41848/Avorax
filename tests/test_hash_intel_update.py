import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "zentor_intel" / "validate_indicator_pack.py"
PACK_BUILDER = ROOT / "tools" / "zentor_intel" / "build_realworld_detection_pack.py"
UPDATE_WRAPPER = ROOT / "tools" / "update" / "avorax-build-hash-intel-update.ps1"


def canonical_pack_bytes(pack: dict) -> bytes:
    canonical = {
        "format": pack["format"],
        "version": pack["version"],
        "compiler_version": pack["compiler_version"],
        "created_at": pack["created_at"],
        "signatures": pack["signatures"],
    }
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")


def known_bad_signature(pattern: str | None = None) -> dict:
    return {
        "id": "ZTI-safe-fixture-0001",
        "name": "Known bad metadata-only test indicator",
        "version": "1",
        "category": "trojan",
        "confidence": "confirmed",
        "severity": "critical",
        "signature_type": "exact_hash",
        "pattern": pattern or hashlib.sha256(b"benign metadata-only fixture").hexdigest(),
        "mask": None,
        "offset": None,
        "file_types": ["*"],
        "min_file_size": None,
        "max_file_size": None,
        "required_context": [],
        "false_positive_notes": "Exact SHA-256 from a reviewed metadata-only fixture.",
        "action_policy": "quarantine_if_policy_allows",
        "created_at": "2026-07-17T00:00:00Z",
        "updated_at": "2026-07-17T00:00:00Z",
    }


def signature_pack(signatures: list[dict]) -> dict:
    pack = {
        "format": "zentor-signature-pack-v1",
        "version": "0.2.0",
        "compiler_version": None,
        "created_at": "2026-07-17T00:00:00Z",
        "pack_sha256": None,
        "signatures": signatures,
    }
    if signatures:
        pack["pack_sha256"] = hashlib.sha256(canonical_pack_bytes(pack)).hexdigest()
    return pack


def write_pack(path: Path, pack: dict) -> None:
    path.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")


def run_python(*arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(argument) for argument in arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def validate_known_bad(path: Path) -> subprocess.CompletedProcess[str]:
    return run_python(VALIDATOR, "--input", path, "--profile", "known-bad-sha256")


def test_known_bad_sha256_profile_accepts_strict_exact_hash_pack():
    with tempfile.TemporaryDirectory(prefix="avorax-hash-profile-") as temp:
        path = Path(temp) / "known-bad.zsig"
        write_pack(path, signature_pack([known_bad_signature()]))

        result = validate_known_bad(path)

        assert result.returncode == 0, result.stderr
        assert "profile known-bad-sha256" in result.stdout


def test_known_bad_sha256_profile_rejects_noncanonical_policy():
    variants = [
        ("signature_type", "partial_hash", "must use exact_hash"),
        ("pattern", "A" * 64, "lowercase 64-character SHA-256"),
        ("confidence", "high", "confidence must be confirmed"),
        ("severity", "high", "severity must be critical"),
        ("action_policy", "observe", "action_policy must be quarantine_if_policy_allows"),
        ("category", "unknown", "production threat category"),
        ("category", "testThreat", "production threat category"),
        ("file_types", ["pe"], "file_types must be exactly"),
        ("required_context", ["pe"], "required_context must be empty"),
        ("mask", "ff", "mask must be null"),
    ]
    with tempfile.TemporaryDirectory(prefix="avorax-hash-policy-") as temp:
        temp_path = Path(temp)
        for index, (field, value, diagnostic) in enumerate(variants):
            item = known_bad_signature()
            item[field] = value
            path = temp_path / f"invalid-{index}.zsig"
            write_pack(path, signature_pack([item]))

            result = validate_known_bad(path)

            assert result.returncode != 0
            assert diagnostic in result.stderr


def test_known_bad_sha256_profile_rejects_empty_and_duplicate_packs():
    with tempfile.TemporaryDirectory(prefix="avorax-hash-duplicates-") as temp:
        temp_path = Path(temp)
        empty_path = temp_path / "empty.zsig"
        write_pack(empty_path, signature_pack([]))
        empty_result = validate_known_bad(empty_path)
        assert empty_result.returncode != 0
        assert "requires at least one signature" in empty_result.stderr

        first = known_bad_signature()
        second = copy.deepcopy(first)
        second["id"] = "ZTI-safe-fixture-0002"
        duplicate_path = temp_path / "duplicate.zsig"
        write_pack(duplicate_path, signature_pack([first, second]))
        duplicate_result = validate_known_bad(duplicate_path)
        assert duplicate_result.returncode != 0
        assert "duplicates SHA-256" in duplicate_result.stderr

        duplicate_id_second = known_bad_signature(
            hashlib.sha256(b"another benign metadata-only fixture").hexdigest()
        )
        duplicate_id_path = temp_path / "duplicate-id.zsig"
        write_pack(duplicate_id_path, signature_pack([first, duplicate_id_second]))
        duplicate_id_result = validate_known_bad(duplicate_id_path)
        assert duplicate_id_result.returncode != 0
        assert "duplicates signature id" in duplicate_id_result.stderr


def test_known_bad_sha256_profile_rejects_uppercase_pack_hash():
    with tempfile.TemporaryDirectory(prefix="avorax-hash-pack-digest-") as temp:
        path = Path(temp) / "uppercase-pack-hash.zsig"
        pack = signature_pack([known_bad_signature()])
        pack["pack_sha256"] = pack["pack_sha256"].upper()
        write_pack(path, pack)

        result = validate_known_bad(path)

        assert result.returncode != 0
        assert "requires a lowercase pack_sha256" in result.stderr


def test_realworld_builder_atomically_activates_only_valid_known_bad_pack():
    with tempfile.TemporaryDirectory(prefix="avorax-hash-build-") as temp:
        temp_path = Path(temp)
        source = temp_path / "source.json"
        hashes = temp_path / "hashes.txt"
        output = temp_path / "reviewed.zsig"
        fixture_hash = hashlib.sha256(b"benign reviewed hash-only fixture").hexdigest()
        source.write_text(
            json.dumps(
                {
                    "source_name": "reviewed hash-only fixture",
                    "source_url": "https://example.invalid/reviewed-hashes",
                    "source_type": "test_fixture",
                    "malware_family": "Fixture.Safe",
                }
            ),
            encoding="utf-8",
        )
        hashes.write_text(fixture_hash + "\n", encoding="utf-8")

        result = run_python(
            PACK_BUILDER,
            "--source",
            source,
            "--hashes",
            hashes,
            "--output",
            output,
            "--category",
            "trojan",
            "--version",
            "0.2.0",
        )

        assert result.returncode == 0, result.stderr
        pack = json.loads(output.read_text(encoding="utf-8"))
        assert [item["pattern"] for item in pack["signatures"]] == [fixture_hash]
        assert not list(temp_path.glob(".*.jsonl"))
        assert not list(temp_path.glob(".*.zsig.tmp"))


def test_realworld_builder_failure_preserves_previous_pack_and_cleans_temps():
    with tempfile.TemporaryDirectory(prefix="avorax-hash-failsafe-") as temp:
        temp_path = Path(temp)
        source = temp_path / "source.json"
        hashes = temp_path / "empty-hashes.txt"
        output = temp_path / "reviewed.zsig"
        source.write_text(
            json.dumps(
                {
                    "source_name": "reviewed empty fixture",
                    "source_type": "test_fixture",
                }
            ),
            encoding="utf-8",
        )
        hashes.write_text("# no reviewed hashes\n", encoding="utf-8")
        previous = b"previous known-good pack remains active\n"
        output.write_bytes(previous)

        result = run_python(
            PACK_BUILDER,
            "--source",
            source,
            "--hashes",
            hashes,
            "--output",
            output,
            "--category",
            "trojan",
            "--version",
            "0.2.0",
        )

        assert result.returncode != 0
        assert "requires at least one signature" in result.stderr
        assert output.read_bytes() == previous
        assert not list(temp_path.glob(".*.jsonl"))
        assert not list(temp_path.glob(".*.zsig.tmp"))


def test_signed_hash_intel_update_wrapper_is_local_bounded_and_signature_only():
    source = UPDATE_WRAPPER.read_text(encoding="utf-8")
    package_builder = (
        ROOT / "tools" / "update" / "avorax-build-update-package.ps1"
    ).read_text(encoding="utf-8")

    assert "AVORAX_UPDATE_SIGNER is required" in source
    assert "build_realworld_detection_pack.py" in source
    assert "avorax-build-update-package.ps1" in source
    assert "Invoke-AvoraxGateCommandDiagnostic" in source
    assert "zentor_reviewed_known_bad.zsig" in source
    assert "must contain exactly one reviewed signature pack" in source
    assert "Assert-NoReparseTree $payloadRoot" in source
    assert "PythonPath must be an absolute local executable path" in source
    assert "Assert-SafePathToken $Version" in source
    assert "Assert-SafePathToken $Channel" in source
    assert 'Remove-CheckedTempTree $builderWork $outputPath' in source
    assert "Remove-CheckedTempTree $tempRoot $tempParent" in source
    assert "Invoke-WebRequest" not in source
    assert "git clone" not in source.lower()
    assert "github.com" not in source.lower()
    assert 'New-CheckedDirectory $payloadDocs "payload docs directory"' in package_builder
