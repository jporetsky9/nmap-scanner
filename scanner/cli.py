"""Command-line interface.

Exit codes: 0 success, 1 one or more hosts failed to scan, 2 usage or scope error.
"""
import argparse
import shutil
import sys

from . import report
from .findings import find_issues
from .runner import PRESETS, scan_all, validate_ports, validate_scripts
from .targets import ScopeError, check_scope, load_targets


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m scanner",
        description=(
            "Scan hosts with nmap in parallel and report open ports, services, and "
            "NSE script output. Only scan systems you own or have written permission to test."
        ),
    )
    parser.add_argument("targets", nargs="*", help="IP address, hostname, or CIDR block")
    parser.add_argument("-f", "--targets-file", help="file with one target per line")
    parser.add_argument("--preset", choices=sorted(PRESETS), help="ports and scripts for web or mail")
    parser.add_argument("-p", "--ports", help="ports, e.g. 22,80,443 or 1-1024 (overrides preset)")
    parser.add_argument("--scripts", help="comma-separated NSE scripts (overrides preset)")
    parser.add_argument("--threads", type=int, default=4, help="parallel scans, 1-16 (default 4)")
    parser.add_argument("--timeout", type=int, default=300, help="seconds per host (default 300)")
    parser.add_argument("--csv", metavar="FILE", help="write results to a CSV file")
    parser.add_argument("--json", metavar="FILE", help="write results to a JSON file")
    parser.add_argument("--show-all", action="store_true", help="include closed and filtered ports")
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="skip host discovery (nmap -Pn); use for hosts that block ping",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="confirm you are authorized to scan targets outside private ranges",
    )
    parser.add_argument("--nmap-path", default="nmap", help="path to the nmap binary")
    return parser


def _progress(done, total, host):
    print(f"[{done}/{total}] finished {report.printable(host)}", file=sys.stderr)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if not 1 <= args.threads <= 16:
            raise ValueError("--threads must be between 1 and 16")
        if args.timeout < 1:
            raise ValueError("--timeout must be at least 1 second")

        hosts = load_targets(args.targets, args.targets_file)
        if not hosts:
            raise ValueError("no targets given (pass targets or --targets-file)")
        check_scope(hosts, args.authorized)

        preset = PRESETS.get(args.preset, {})
        ports = validate_ports(args.ports or preset.get("ports"))
        scripts = validate_scripts(args.scripts or preset.get("scripts"))
    except (ValueError, OSError) as err:  # ScopeError is a ValueError
        print(f"error: {err}", file=sys.stderr)
        return 2

    if shutil.which(args.nmap_path) is None:
        print(f"error: nmap not found ({args.nmap_path}); install it first", file=sys.stderr)
        return 2

    results = scan_all(
        hosts,
        threads=args.threads,
        ports=ports,
        scripts=scripts,
        timeout=args.timeout,
        nmap_path=args.nmap_path,
        progress=_progress,
        no_ping=args.no_ping,
    )
    issues = find_issues(results)

    print(report.render_table(results, args.show_all))
    print()
    print(report.render_summary(results))
    print()
    print(report.render_findings(issues, results))
    if args.csv:
        report.write_csv(results, args.csv, args.show_all)
    if args.json:
        report.write_json(results, args.json, issues)

    return 1 if any(r.status == "error" for r in results) else 0
