"""
Manifest and Cryptographic Checksum Verification Tests.

Validates manifest.sha256 integrity, completeness, tamper detection,
and confirms absence of CAL/TEST data in the DEV handoff package.
"""

import hashlib
from pathlib import Path


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def test_manifest_checksums_match_all_files() -> None:
    """Validates that every file listed in manifest.sha256 has matching cryptographic checksum."""
    dev_dir = Path("experiments/datasets/dev")
    manifest_file = dev_dir / "manifest.sha256"

    assert manifest_file.exists(), "manifest.sha256 does not exist."

    entries: dict[str, str] = {}
    for line in manifest_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.strip().split()
        assert len(parts) == 2, f"Malformed manifest line: {line}"
        sha, filename = parts[0], parts[1]
        entries[filename] = sha

    expected_files = {
        "README.md",
        "h1_impl.py",
        "h1_manipulation_check.json",
        "information_barrier_audit.json",
        "label_audit.jsonl",
        "labels.jsonl",
        "protocol.md",
        "provenance.json",
        "split_isolation.json",
        "traces.jsonl",
    }

    assert set(entries.keys()) == expected_files, (
        f"Manifest keys mismatch: {set(entries.keys())} vs {expected_files}"
    )

    for filename, expected_sha in entries.items():
        target_path = dev_dir / filename
        assert target_path.exists(), f"Delivered file missing: {filename}"
        actual_sha = compute_sha256(target_path)
        assert actual_sha == expected_sha, (
            f"SHA mismatch for {filename}: expected {expected_sha}, got {actual_sha}"
        )


def test_no_untracked_files_in_dev_package() -> None:
    """Ensures no extra or rogue files exist in the DEV delivery directory."""
    dev_dir = Path("experiments/datasets/dev")
    actual_files = {p.name for p in dev_dir.iterdir() if p.is_file()}

    allowed_files = {
        "README.md",
        "h1_impl.py",
        "h1_manipulation_check.json",
        "information_barrier_audit.json",
        "label_audit.jsonl",
        "labels.jsonl",
        "manifest.sha256",
        "protocol.md",
        "provenance.json",
        "split_isolation.json",
        "traces.jsonl",
    }

    unexpected = actual_files - allowed_files
    assert not unexpected, f"Unexpected files found in DEV package: {unexpected}"


def test_no_cal_or_test_traces_in_dev_package() -> None:
    """Confirms no CAL or TEST trace markers exist in manifest or filenames."""
    dev_dir = Path("experiments/datasets/dev")
    manifest_file = dev_dir / "manifest.sha256"
    content = manifest_file.read_text(encoding="utf-8").lower()

    assert "cal" not in content, "CAL trace references detected in manifest!"
    assert "test" not in content, "TEST trace references detected in manifest!"

def test_held_out_splits_manifest_integrity() -> None:
    """Validates that CAL, TEST-IN, and TEST-NOVEL have cryptographically valid manifests."""
    base_dir = Path("experiments/datasets")
    for split_name in ("cal", "test-in", "test-novel"):
        split_dir = base_dir / split_name
        manifest_file = split_dir / "manifest.sha256"
        assert manifest_file.exists(), f"Missing manifest for {split_name}"

        entries: dict[str, str] = {}
        for line in manifest_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            sha, filename = line.strip().split()
            entries[filename] = sha

        expected = {
            "README.md", "label_audit.jsonl", "labels.jsonl",
            "provenance.json", "split_isolation.json", "traces.jsonl",
        }
        mismatch_msg = f"Mismatch in {split_name}: {set(entries.keys())} vs {expected}"
        assert set(entries.keys()) == expected, mismatch_msg

        for filename, expected_sha in entries.items():
            fpath = split_dir / filename
            assert fpath.exists()
            actual_sha = compute_sha256(fpath)
            assert actual_sha == expected_sha, f"SHA mismatch in {split_name}/{filename}"


def test_test_commitment_integrity() -> None:
    """Validates docs/prereg/TEST_COMMITMENT.sha256 sealed digests."""
    commitment_file = Path("docs/prereg/TEST_COMMITMENT.sha256")
    assert commitment_file.exists(), "TEST_COMMITMENT.sha256 does not exist!"

    for line in commitment_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected_sha, rel_path = line.strip().split()
        fpath = Path(rel_path)
        assert fpath.exists(), f"Committed file missing: {rel_path}"
        actual_sha = compute_sha256(fpath)
        assert actual_sha == expected_sha, f"Commitment digest mismatch for {rel_path}"
