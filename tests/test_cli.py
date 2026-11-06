from pathlib import Path

import pytest

from scanner import cli
from scanner.runner import parse_nmap_xml

FIXTURE = (Path(__file__).parent / "fixtures" / "sample_scan.xml").read_text()


@pytest.fixture(autouse=True)
def fake_nmap(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda path: "/usr/bin/nmap")
    calls = {}

    def fake_scan_all(hosts, **kwargs):
        calls["hosts"] = hosts
        calls.update(kwargs)
        return [parse_nmap_xml(FIXTURE, host) for host in hosts]

    monkeypatch.setattr(cli, "scan_all", fake_scan_all)
    return calls


def test_scan_prints_table_and_summary(capsys):
    assert cli.main(["192.168.1.10"]) == 0
    out = capsys.readouterr().out
    assert "22/tcp" in out
    assert "Hosts scanned: 1" in out


def test_preset_supplies_ports_and_scripts(fake_nmap):
    cli.main(["192.168.1.10", "--preset", "web"])
    assert fake_nmap["ports"] == "80,443,8080,8443"
    assert "ssl-cert" in fake_nmap["scripts"]


def test_explicit_ports_override_preset(fake_nmap):
    cli.main(["192.168.1.10", "--preset", "web", "-p", "22"])
    assert fake_nmap["ports"] == "22"


def test_public_target_is_refused_without_authorized(capsys, fake_nmap):
    assert cli.main(["8.8.8.8"]) == 2
    assert "--authorized" in capsys.readouterr().err
    assert "hosts" not in fake_nmap  # nothing was scanned


def test_public_target_allowed_with_authorized(fake_nmap):
    assert cli.main(["8.8.8.8", "--authorized"]) == 0
    assert fake_nmap["hosts"] == ["8.8.8.8"]


def test_bad_input_returns_usage_error(capsys):
    assert cli.main(["192.168.1.1", "-p", "80;id"]) == 2
    assert cli.main(["192.168.1.1", "--threads", "99"]) == 2
    assert cli.main([]) == 2


def test_missing_nmap_is_a_clear_error(monkeypatch, capsys):
    monkeypatch.setattr(cli.shutil, "which", lambda path: None)
    assert cli.main(["192.168.1.1"]) == 2
    assert "nmap not found" in capsys.readouterr().err


def test_no_ping_is_passed_through(fake_nmap):
    cli.main(["192.168.1.10", "--no-ping"])
    assert fake_nmap["no_ping"] is True


def test_findings_section_is_printed(capsys):
    cli.main(["192.168.1.10"])
    assert "Findings" in capsys.readouterr().out


def test_writes_output_files(tmp_path):
    csv_path, json_path = tmp_path / "r.csv", tmp_path / "r.json"
    assert cli.main(["192.168.1.10", "--csv", str(csv_path), "--json", str(json_path)]) == 0
    assert csv_path.exists() and json_path.exists()
