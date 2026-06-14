"""Phase-7 packaging + docs acceptance tests."""

from __future__ import annotations

import importlib
import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


# --- public API has no dangling exports (acceptance #1) -------------------- #
def test_all_exports_are_importable():
    pqlens = importlib.import_module("pqlens")
    assert pqlens.__all__
    for name in pqlens.__all__:
        assert hasattr(pqlens, name), f"pqlens.__all__ lists {name!r} but it is missing"


def test_data_tables_are_package_resources():
    from importlib import resources

    for fname in ("algorithms.json", "compliance.json"):
        assert resources.files("pqlens.data").joinpath(fname).is_file()


def test_py_typed_marker_present():
    assert (ROOT / "src" / "pqlens" / "py.typed").exists()


# --- README leads with "does NOT do" (acceptance #4) ----------------------- #
def test_readme_first_h2_is_does_not_do():
    lines = (ROOT / "README.md").read_text("utf-8").splitlines()
    first_h2 = next(line for line in lines if line.startswith("## "))
    assert "not do" in first_h2.lower(), f"first H2 was {first_h2!r}"


def test_license_file_present_and_apache():
    text = (ROOT / "LICENSE").read_text("utf-8")
    assert "Apache License" in text
    assert "Version 2.0" in text


# --- built wheel ships the data files (acceptance #2) ---------------------- #
@pytest.mark.skipif(
    importlib.util.find_spec("build") is None or importlib.util.find_spec("hatchling") is None,
    reason="needs 'build' + 'hatchling' to assemble a wheel",
)
def test_built_wheel_contains_data_and_typing(tmp_path):
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(tmp_path)],
        cwd=ROOT, check=True, capture_output=True,
    )
    wheels = list(tmp_path.glob("*.whl"))
    assert wheels, "no wheel was produced"
    with zipfile.ZipFile(wheels[0]) as zf:
        names = zf.namelist()
    assert any(n.endswith("pqlens/data/algorithms.json") for n in names), names
    assert any(n.endswith("pqlens/data/compliance.json") for n in names), names
    assert any(n.endswith("pqlens/py.typed") for n in names), names
