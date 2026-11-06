"""Turn scan results into a terminal table, CSV, or JSON.

Scan output contains text controlled by the remote host (banners, page titles),
so it is treated as untrusted:
  * control characters are stripped before printing, so a banner can't inject
    terminal escape sequences;
  * CSV cells that start with a formula character are prefixed with a quote, so
    opening the file in a spreadsheet can't run a formula.
"""
import csv
import json
import re
from collections import Counter
from dataclasses import asdict

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
BAR_WIDTH = 30


def printable(text):
    return _CONTROL_RE.sub("?", str(text))


def csv_safe(value):
    value = str(value)
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


def _visible_ports(results, show_all):
    for host in results:
        for port in host.ports:
            if show_all or port.state == "open":
                yield host, port


def render_table(results, show_all=False):
    rows = [("HOST", "PORT", "STATE", "SERVICE", "VERSION")]
    for host, port in _visible_ports(results, show_all):
        rows.append(
            tuple(
                printable(cell)
                for cell in (
                    host.host,
                    f"{port.port}/{port.protocol}",
                    port.state,
                    port.service,
                    port.version_string(),
                )
            )
        )
    if len(rows) == 1:
        return "No open ports found."

    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
             for row in rows]
    lines.insert(1, "  ".join("-" * width for width in widths))
    return "\n".join(lines)


def render_summary(results):
    up = sum(1 for r in results if r.status == "up")
    errors = [r for r in results if r.status == "error"]
    lines = [
        f"Hosts scanned: {len(results)}   up: {up}   "
        f"down: {sum(1 for r in results if r.status == 'down')}   errors: {len(errors)}"
    ]
    for result in errors:
        lines.append(f"  error on {printable(result.host)}: {printable(result.error)}")

    open_counts = Counter(
        f"{p.port}/{p.protocol}" for r in results for p in r.ports if p.state == "open"
    )
    if open_counts:
        lines.append("")
        lines.append("Most common open ports:")
        top = open_counts.most_common(5)
        biggest = top[0][1]
        for label, count in top:
            bar = "#" * max(1, round(BAR_WIDTH * count / biggest))
            lines.append(f"  {label:<10} {bar} {count}")
    return "\n".join(lines)


def write_csv(results, path, show_all=False):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "port", "protocol", "state", "service", "version", "scripts"])
        for host, port in _visible_ports(results, show_all):
            scripts = " | ".join(f"{name}: {out}" for name, out in port.scripts.items())
            writer.writerow(
                [
                    csv_safe(host.host),
                    port.port,
                    port.protocol,
                    csv_safe(port.state),
                    csv_safe(port.service),
                    csv_safe(port.version_string()),
                    csv_safe(" ".join(scripts.split())),
                ]
            )


def write_json(results, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([asdict(result) for result in results], handle, indent=2)
