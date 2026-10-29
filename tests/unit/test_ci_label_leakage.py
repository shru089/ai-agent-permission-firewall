"""
Tests for portable CI check scripts/ci_check_no_labels.py.
Verifies exit codes: 0 (clean), 1 (tracked label violation), 2 (git execution failure).
"""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "ci_check_no_labels.py"


@pytest.mark.unit
def test_ci_check_script_clean_repo(tmp_path: Path) -> None:
    """CI check exits 0 when no labels.sqlite is tracked."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "TestUser"], cwd=tmp_path, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    dummy_file = tmp_path / "valid_code.py"
    dummy_file.write_text("print('hello')", encoding="utf-8")
    subprocess.run(["git", "add", "valid_code.py"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True, capture_output=True)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)], cwd=tmp_path, capture_output=True, text=True
    )
    assert proc.returncode == 0
    assert "No labels.sqlite tracked in git" in proc.stdout


@pytest.mark.unit
def test_ci_check_script_root_violation(tmp_path: Path) -> None:
    """CI check exits 1 when labels.sqlite is tracked at root."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "TestUser"], cwd=tmp_path, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    label_file = tmp_path / "labels.sqlite"
    label_file.write_bytes(b"dummy_sqlite_content")
    subprocess.run(["git", "add", "labels.sqlite"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add labels"], cwd=tmp_path, check=True, capture_output=True
    )

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)], cwd=tmp_path, capture_output=True, text=True
    )
    assert proc.returncode == 1
    assert "SECURITY VIOLATION" in proc.stderr


@pytest.mark.unit
def test_ci_check_script_nested_violation(tmp_path: Path) -> None:
    """CI check exits 1 when labels.sqlite is tracked in a subdirectory."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "TestUser"], cwd=tmp_path, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    nested_dir = tmp_path / "data" / "test"
    nested_dir.mkdir(parents=True)
    label_file = nested_dir / "labels.sqlite"
    label_file.write_bytes(b"dummy_sqlite_content")
    subprocess.run(
        ["git", "add", "data/test/labels.sqlite"], cwd=tmp_path, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "add nested labels"], cwd=tmp_path, check=True, capture_output=True
    )

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)], cwd=tmp_path, capture_output=True, text=True
    )
    assert proc.returncode == 1
    assert "SECURITY VIOLATION" in proc.stderr


@pytest.mark.unit
def test_ci_check_script_command_failure(tmp_path: Path) -> None:
    """CI check exits 2 when run outside a git repository."""
    non_git_dir = tmp_path / "not_a_repo"
    non_git_dir.mkdir()

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)], cwd=non_git_dir, capture_output=True, text=True
    )
    assert proc.returncode == 2
    assert "CI ERROR" in proc.stderr
