"""Target parsing, validation, and scope checks.

Targets are validated here so that nothing user-supplied can be mistaken for an
nmap option, and so the tool refuses to scan outside private address space unless
the operator explicitly confirms they are authorized.
"""
import ipaddress
import re

MAX_HOSTS = 256
# nmap.org runs scanme.nmap.org specifically so people can test scanners on it.
ALLOWED_PUBLIC_NAMES = {"scanme.nmap.org"}

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$", re.IGNORECASE)
_DOTTED_NUMBERS_RE = re.compile(r"^[0-9.]+$")


class ScopeError(ValueError):
    """Raised when targets fall outside the default (private) scope."""


def expand_target(spec):
    """Turn one IP, CIDR block, or hostname into a list of host strings."""
    spec = spec.strip()
    if not spec:
        return []

    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError as err:
            raise ValueError(f"invalid network: {spec!r}") from err
        if network.num_addresses > MAX_HOSTS:
            raise ValueError(f"{spec} covers more than {MAX_HOSTS} addresses")
        return [str(host) for host in network.hosts()]

    try:
        return [str(ipaddress.ip_address(spec))]
    except ValueError:
        pass

    # Reject things like "10.0.0.256", which look numeric but are not valid IPs.
    if _DOTTED_NUMBERS_RE.match(spec):
        raise ValueError(f"invalid target: {spec!r}")
    if len(spec) <= 253 and _HOSTNAME_RE.match(spec):
        return [spec.lower()]
    raise ValueError(f"invalid target: {spec!r}")


def load_targets(specs, file_path=None):
    """Expand command-line targets and an optional file (one per line, # comments)."""
    raw = list(specs)
    if file_path:
        with open(file_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)

    hosts = []
    for spec in raw:
        hosts.extend(expand_target(spec))
    # De-duplicate but keep the order the user gave.
    return list(dict.fromkeys(hosts))


def in_default_scope(host):
    """True for private, loopback, and link-local addresses and allow-listed names."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in ALLOWED_PUBLIC_NAMES
    # Judge an IPv4-mapped IPv6 address (::ffff:8.8.8.8) by the IPv4 address inside
    # it. Some Python versions treat every mapped address as private.
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_private or address.is_loopback or address.is_link_local


def check_scope(hosts, authorized=False):
    """Raise ScopeError if any host is out of scope and --authorized wasn't given."""
    if authorized:
        return
    outside = [host for host in hosts if not in_default_scope(host)]
    if outside:
        shown = ", ".join(outside[:5]) + (" ..." if len(outside) > 5 else "")
        raise ScopeError(
            f"refusing to scan outside private ranges without --authorized: {shown}"
        )
