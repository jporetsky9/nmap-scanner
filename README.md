# nmap-scanner

A multi-threaded Python command-line tool that runs [nmap](https://nmap.org) against many
hosts at once, uses the Nmap Scripting Engine (NSE) to check web and mail services, and
produces a readable table plus CSV and JSON reports.

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

# Mail services on hosts from a file (one per line, # comments allowed)
python -m scanner -f lab_hosts.txt --preset mail

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
| `--authorized` | Confirm permission to scan outside private ranges |

Exit codes: `0` success, `1` at least one host failed to scan, `2` usage or scope error.

## Example output

Rendered from the sample XML in `tests/fixtures/sample_scan.xml`:

```
HOST          PORT     STATE  SERVICE  VERSION
------------  -------  -----  -------  -------------
192.168.1.10  22/tcp   open   ssh      OpenSSH 8.9p1
192.168.1.10  80/tcp   open   http     nginx 1.18.0
192.168.1.10  443/tcp  open   https    nginx 1.18.0

Hosts scanned: 1   up: 1   down: 0   errors: 0

Most common open ports:
  22/tcp     ############################## 1
  80/tcp     ############################## 1
  443/tcp    ############################## 1
```

## How it works

```
CLI --> target parsing + scope check --> thread pool --> one nmap process per host
                                                              |
                                                       XML (-oX -) parsed
                                                              |
                                              table / summary / CSV / JSON
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
- **Parallelism with bounded workers.** One nmap process per host, capped at 16 threads
  so a large scan can't swamp the machine or the network.

## Tests

```bash
pip install pytest
pytest -q
```

The tests mock `subprocess` and parse a saved nmap XML sample, so they run without nmap
and without touching any network.

## Limitations and ideas

- Targets are scanned one nmap process per host, so very large ranges are slow.
- IPv6 networks are accepted but only practical for small blocks.
- Ideas: diff two scan runs to show newly opened ports, an HTML report, and a
  `--rate-limit` option.
