# nmap-scanner

A multi-threaded Python command-line tool that runs [nmap](https://nmap.org) against many
hosts at once, uses the Nmap Scripting Engine (NSE) to check web and mail services, flags
common TLS, HTTP, and mail misconfigurations, compares them across hosts, and writes CSV and
JSON reports.

Python 3.9+ (standard library only), nmap.

> **Background.** During a security internship I built a Python scanner that used nmap and
> NSE to assess exposed web and mail services. This repo is a clean rewrite with a focus on
> safe defaults. It contains no code or data from that work.

## Use it responsibly

Only scan systems you own or have **written permission** to test. Unauthorized scanning
can be illegal and can disrupt services.

The tool enforces this by default: it refuses any target outside private address ranges
(RFC 1918, loopback, link-local) except `scanme.nmap.org`, which nmap.org provides for
testing. To scan anything else you must pass `--authorized`, confirming you have permission.

## Install

```bash
# 1. Install nmap (Debian/Ubuntu: apt install nmap, macOS: brew install nmap)
# 2. Clone this repo. There are no Python packages to install.
python -m scanner --help
```

## Usage

```bash
# One host, default nmap ports, service/version detection
python -m scanner 192.168.1.10

# A /24 lab network, web checks, 8 parallel scans, saved reports
python -m scanner 192.168.1.0/24 --preset web --threads 8 --csv web.csv --json web.json

# Mail services on hosts from a file (one per line, # comments allowed).
# --no-ping because mail servers often don't answer nmap's default discovery probes.
python -m scanner -f lab_hosts.txt --preset mail --no-ping

# Custom ports and NSE scripts
python -m scanner 192.168.1.10 -p 1-1024 --scripts http-title,ssl-cert

# Practice target provided by nmap.org
python -m scanner scanme.nmap.org --preset web
```

### Options

| Option | Description |
| --- | --- |
| `targets` | IP addresses, hostnames, or CIDR blocks (up to 256 addresses each) |
| `-f, --targets-file` | File with one target per line |
| `--preset web\|mail` | Ports and NSE scripts for common web or mail checks |
| `-p, --ports` | Ports, e.g. `22,80,443` or `1-1024` (overrides preset) |
| `--scripts` | Comma-separated NSE scripts (overrides preset) |
| `--threads` | Parallel scans, 1 to 16 (default 4) |
| `--timeout` | Seconds allowed per host (default 300) |
| `--csv FILE`, `--json FILE` | Write results to a file |
| `--show-all` | Include closed and filtered ports |
| `--no-ping` | Skip host discovery (`nmap -Pn`) for hosts that block ping |
| `--authorized` | Confirm permission to scan outside private ranges |

Exit codes: `0` success, `1` at least one host failed to scan, `2` usage or scope error.

## Example output

A `--preset web` scan of a lab web server with an outdated TLS setup:

```
HOST          PORT     STATE  SERVICE   VERSION
------------  -------  -----  --------  ------------
192.168.1.10  80/tcp   open   http      nginx 1.18.0
192.168.1.10  443/tcp  open   ssl/http  nginx 1.18.0

Hosts scanned: 1   up: 1   down: 0   errors: 0

Most common open ports:
  80/tcp     ############################## 1
  443/tcp    ############################## 1

Findings (4):
  MEDIUM  192.168.1.10  443/tcp  TLS 1.0/1.1 enabled                 TLSv1.0
  MEDIUM  192.168.1.10  443/tcp  Weak cipher suites offered          weakest cipher graded C
  LOW     192.168.1.10  443/tcp  Certificate expires within 30 days  expires 2026-11-20
  LOW     192.168.1.10  443/tcp  HTTPS without HSTS header           no Strict-Transport-Security header

Hosts affected (of 1 up):
  TLS 1.0/1.1 enabled                      1
  Weak cipher suites offered               1
  Certificate expires within 30 days       1
  HTTPS without HSTS header                1
```

With many hosts, "Hosts affected" is the comparison: how many of the scanned servers share
each problem.

## Findings

The checks read the output of the NSE scripts in the scan. Each runs only when its script
ran, so a missing script never produces a finding.

| Check | Severity | Needs script |
| --- | --- | --- |
| SSLv2/SSLv3 enabled | high | `ssl-enum-ciphers` |
| TLS 1.0/1.1 enabled | medium | `ssl-enum-ciphers` |
| Weakest cipher graded C (medium) or D to F (high) | medium/high | `ssl-enum-ciphers` |
| Certificate expired (high) or expiring within 30 days (low) | high/low | `ssl-cert` |
| HTTPS without a `Strict-Transport-Security` header | low | `http-headers` |
| SMTP on 25/587 without STARTTLS | medium | `smtp-commands` |

These are heuristics on script text. Confirm a finding before you report it.

## How it works

```
CLI --> target parsing + scope check --> thread pool --> one nmap process per host
                                                              |
                                                       XML (-oX -) parsed
                                                              |
                                         table / summary / findings / CSV / JSON
```

## Design decisions

- **Targets can't become options.** Targets and port/script lists are validated against
  strict patterns, so input like `-oN /tmp/x` is rejected instead of being passed to nmap.
- **No shell.** nmap is launched with an argument list, never a shell string.
- **Scope guard.** Out-of-scope targets are refused unless the operator opts in.
- **Safe to run on hostile networks.** Banners and page titles come from remote hosts,
  so control characters are stripped before printing (no terminal escape injection), and
  CSV cells starting with `=`, `+`, `-`, or `@` are prefixed with a quote (no spreadsheet
  formula injection).
- **Failures don't stop the run.** A timeout or unresolvable host becomes an `error` row
  in the report and the other hosts continue.
- **Discovery can be skipped.** Without root, nmap decides a host is up by trying ports
  80 and 443, so a mail-only server can look down. `--no-ping` passes `-Pn`, and the
  summary suggests it whenever a host shows as down.
- **Unresolvable names are errors, not "down".** nmap exits 0 when a hostname doesn't
  resolve, so the parser checks the run statistics to tell the two apart.
- **IPv6 handled explicitly.** IPv6 targets get nmap's `-6` flag, and an IPv4-mapped
  address (`::ffff:8.8.8.8`) is scope-checked as the IPv4 address it contains.
- **Parallelism with bounded workers.** One nmap process per host, capped at 16 threads
  so a large scan can't swamp the machine or the network.

## Tests

```bash
pip install pytest
pytest -q
```

The tests mock `subprocess` and parse a saved nmap XML sample, so they run without nmap
and without touching any network. GitHub Actions runs them on Python 3.9, 3.11, and 3.13
for every push (`.github/workflows/tests.yml`).

## Limitations and ideas

- Targets are scanned one nmap process per host, so very large ranges are slow.
- IPv6 networks are accepted but only practical for small blocks.
- Findings parse NSE text output, which can change between nmap versions.
- Ideas: diff two scan runs to show newly opened ports, an HTML report, and a
  `--rate-limit` option.
