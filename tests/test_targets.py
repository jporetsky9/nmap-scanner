import pytest

from scanner.targets import (
    ScopeError,
    check_scope,
    expand_target,
    in_default_scope,
    load_targets,
)


def test_single_ip_and_hostname():
    assert expand_target("192.168.1.5") == ["192.168.1.5"]
    assert expand_target("Scanme.Nmap.Org") == ["scanme.nmap.org"]


def test_cidr_expands_to_usable_hosts():
    assert expand_target("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_single_host_cidr():
    assert expand_target("10.0.0.7/32") == ["10.0.0.7"]


def test_oversized_network_is_rejected():
    with pytest.raises(ValueError):
        expand_target("10.0.0.0/16")


@pytest.mark.parametrize(
    "bad", ["-oN /tmp/x", "-sS", "a b", "host;rm -rf", "10.0.0.256", "bad..name", "$(id)"]
)
def test_invalid_targets_are_rejected(bad):
    with pytest.raises(ValueError):
        expand_target(bad)


def test_load_targets_reads_file_ignores_comments_and_dedupes(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# lab\n10.0.0.1\n\n10.0.0.2  # router\n10.0.0.1\n")
    assert load_targets(["10.0.0.3"], str(path)) == ["10.0.0.3", "10.0.0.1", "10.0.0.2"]


def test_default_scope():
    assert in_default_scope("192.168.0.1")
    assert in_default_scope("127.0.0.1")
    assert in_default_scope("scanme.nmap.org")
    assert not in_default_scope("8.8.8.8")
    assert not in_default_scope("example.com")


def test_scope_check_blocks_public_targets_unless_authorized():
    with pytest.raises(ScopeError):
        check_scope(["192.168.0.1", "8.8.8.8"])
    check_scope(["192.168.0.1", "8.8.8.8"], authorized=True)
    check_scope(["192.168.0.1", "scanme.nmap.org"])
