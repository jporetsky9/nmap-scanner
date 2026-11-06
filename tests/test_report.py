import csv
import json
from pathlib import Path

from scanner import report
from scanner.runner import HostResult, PortResult, parse_nmap_xml

FIXTURE = (Path(__file__).parent / "fixtures" / "sample_scan.xml").read_text()


def sample_results():
    return [parse_nmap_xml(FIXTURE, "192.168.1.10")]


def test_table_lists_only_open_ports_by_default():
    table = report.render_table(sample_results())
    assert "22/tcp" in table and "443/tcp" in table
    assert "25/tcp" not in table
    assert "closed" not in table


def test_table_show_all_includes_closed_ports():
    assert "25/tcp" in report.render_table(sample_results(), show_all=True)


def test_table_with_nothing_open():
    assert report.render_table([HostResult("10.0.0.1", "up")]) == "No open ports found."


def test_summary_counts_hosts_errors_and_top_ports():
    results = sample_results() + [
        HostResult("10.0.0.2", "down"),
        HostResult("10.0.0.3", "error", error="timed out after 5s"),
    ]
    summary = report.render_summary(results)
    assert "Hosts scanned: 3   up: 1   down: 1   errors: 1" in summary
    assert "error on 10.0.0.3: timed out after 5s" in summary
    assert "Most common open ports:" in summary


def test_terminal_escape_sequences_are_neutralised():
    hostile = HostResult(
        "10.0.0.5", "up",
        [PortResult(80, "tcp", "open", "http", "evil\x1b[2J server", "1.0")],
    )
    table = report.render_table([hostile])
    assert "\x1b" not in table


def test_csv_neutralises_formula_injection(tmp_path):
    hostile = HostResult(
        "10.0.0.5", "up",
        [PortResult(80, "tcp", "open", "http", "=HYPERLINK(1)", "", {"http-title": "+cmd"})],
    )
    path = tmp_path / "out.csv"
    report.write_csv([hostile], str(path))

    rows = list(csv.DictReader(path.open()))
    assert rows[0]["version"].startswith("'=")
    assert rows[0]["scripts"] == "http-title: +cmd"  # begins with a letter, left alone


def test_csv_columns_and_rows(tmp_path):
    path = tmp_path / "out.csv"
    report.write_csv(sample_results(), str(path))
    rows = list(csv.DictReader(path.open()))
    assert [r["port"] for r in rows] == ["22", "80", "443"]
    assert rows[1]["scripts"] == "http-title: Welcome to nginx!"


def test_json_round_trip(tmp_path):
    path = tmp_path / "out.json"
    report.write_json(sample_results(), str(path))
    data = json.loads(path.read_text())
    assert data["hosts"][0]["host"] == "192.168.1.10"
    assert data["hosts"][0]["ports"][0]["service"] == "ssh"
    assert data["findings"] == []


def test_tls_service_shows_as_ssl_prefixed():
    port = PortResult(443, "tcp", "open", "http", "nginx", "", tunnel="ssl")
    assert "ssl/http" in report.render_table([HostResult("10.0.0.5", "up", [port])])


def test_summary_suggests_no_ping_when_hosts_are_down():
    summary = report.render_summary([HostResult("10.0.0.2", "down")])
    assert "--no-ping" in summary
