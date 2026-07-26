"""CLI surface tests for `python -m pqlens`."""

from __future__ import annotations

import pytest

from pqlens.__main__ import main
from pqlens.backends import available_backends


def _have_backend() -> bool:
    return len(available_backends()) > 0


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "pqlens" in capsys.readouterr().out


def test_backends_command(capsys):
    rc = main(["--backends"])
    if _have_backend():
        assert rc == 0
        assert "openssl" in capsys.readouterr().out
    else:  # pragma: no cover - env dependent
        assert rc == 1


@pytest.mark.skipif(not _have_backend(), reason="no audited KEM backend")
def test_selftest_command(capsys):
    rc = main(["--selftest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("PASS")
    assert "match=True" in out


def test_measure_command_human(capsys):
    rc = main(["--measure", "--algorithms", "ML-KEM-768,X-Wing", "--iterations", "5"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "migration cost vs X25519" in out
    assert "ML-KEM-768" in out
    assert "X-Wing" in out
    assert "handshake" in out


def test_measure_command_json(capsys):
    import json

    rc = main(["--measure", "--algorithms", "ML-KEM-512", "--iterations", "5", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["baseline"] == "X25519"
    assert payload["algorithms"][0]["algorithm"] == "ML-KEM-512"
    assert payload["algorithms"][0]["handshake_delta_bytes"] > 0


def test_measure_command_unknown_algorithm(capsys):
    rc = main(["--measure", "--algorithms", "RSA-2048"])
    assert rc == 2
    assert "MEASURE ERROR" in capsys.readouterr().err


def test_no_args_prints_help(capsys):
    rc = main([])
    assert rc == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_scan_command_human(capsys):
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    rc = main(["--scan", str(fixtures)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pqlens scan" in out
    assert "quantum-vulnerable" in out
    assert "limitations" in out


def test_scan_command_json(capsys):
    import json
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    rc = main(["--scan", str(fixtures), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload
    assert payload["limitations"]


@pytest.mark.skipif(not _have_backend(), reason="no audited KEM backend")
def test_hybrid_selftest_command(capsys):
    rc = main(["--hybrid-selftest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("PASS")
    assert "hybrid KEM(ML-KEM-768+X25519)=True" in out
    assert "hybrid SIG(ML-DSA-65+Ed25519)=True" in out


def test_entropy_command_human(capsys, tmp_path):
    import os

    f = tmp_path / "sample.bin"
    f.write_bytes(os.urandom(4096))
    rc = main(["--entropy", str(f)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "entropy assessment" in out
    assert "min-entropy" in out
    assert "caveats" in out


def test_entropy_command_json(capsys, tmp_path):
    import json
    import os

    f = tmp_path / "sample.bin"
    f.write_bytes(os.urandom(2048))
    rc = main(["--entropy", str(f), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sample_bytes"] == 2048
    assert "min_entropy_bits_per_byte" in payload
    assert payload["caveats"]


def test_entropy_command_missing_file(capsys):
    rc = main(["--entropy", "/no/such/sample.bin"])
    assert rc == 2
    assert "ENTROPY ERROR" in capsys.readouterr().err


def _fixtures() -> str:
    from pathlib import Path

    return str(Path(__file__).parent / "fixtures")


def test_compliance_command_human(capsys):
    rc = main(["--compliance", _fixtures()])
    assert rc == 0
    out = capsys.readouterr().out
    assert "compliance evidence" in out
    assert "CNSA-2.0" in out
    assert "UNSIGNED DRAFT" in out


def test_compliance_command_json(capsys):
    import json

    rc = main(["--compliance", _fixtures(), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["signature"] is None
    assert any(s["standard"] == "FIPS-203" for s in payload["standards"])


@pytest.mark.skipif(not _have_backend(), reason="no audited signature backend")
def test_compliance_command_signed_verifies(capsys):
    rc = main(["--compliance", _fixtures(), "--sign"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "signature verifies: True" in out


def test_compliance_command_writes_html(capsys, tmp_path):
    html = tmp_path / "report.html"
    rc = main(["--compliance", _fixtures(), "--html", str(html)])
    assert rc == 0
    assert html.read_text().startswith("<!doctype html>")
