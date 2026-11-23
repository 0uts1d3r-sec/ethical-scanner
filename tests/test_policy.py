"""Request policy of the CLI: scope file, rate limit (--delay) and --timeout."""
import json
import time

import pytest
import requests

import ethical_scanner_cli as cli

DEAD = "http://127.0.0.1:9"  # nothing listens here
HOME = {"/": (200, "<html></html>", {})}
ADMIN = {"/": (200, "<html></html>", {}), "/admin": (200, "ok", {})}


def scope_of(*lines):
    return cli.Scope(lines, "test")


@pytest.fixture
def scope_file(tmp_path):
    def make(*lines):
        path = tmp_path / "scope.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    return make


# ---------------------------------------------------------------- Scope parsing
def test_exact_host_is_allowed_and_lookalikes_are_not():
    scope = scope_of("example.com")
    assert scope.allows("example.com")
    assert scope.allows("EXAMPLE.com")
    assert scope.allows("example.com.")
    assert not scope.allows("evil-example.com")
    assert not scope.allows("sub.example.com")


def test_wildcard_matches_subdomains_but_not_the_apex():
    scope = scope_of("*.example.com")
    assert scope.allows("a.example.com")
    assert scope.allows("a.b.example.com")
    assert not scope.allows("example.com")
    assert not scope.allows("badexample.com")
    assert not scope.allows("example.com.evil.net")


def test_ip_and_cidr_entries():
    scope = scope_of("10.0.0.5", "192.168.1.0/24")
    assert scope.allows("10.0.0.5")
    assert not scope.allows("10.0.0.6")
    assert scope.allows("192.168.1.77")
    assert not scope.allows("192.168.2.1")


def test_comments_blank_lines_urls_and_ports_are_tolerated():
    scope = scope_of("# header", "", "  https://app.example.com/login  # staging",
                     "api.example.com:8443")
    assert scope.allows("app.example.com")
    assert scope.allows("api.example.com")


def test_empty_scope_is_an_error():
    with pytest.raises(ValueError):
        scope_of("# nothing here", "")


def test_a_missing_host_is_never_allowed():
    assert not scope_of("example.com").allows(None)
    assert not scope_of("example.com").allows("")


# ---------------------------------------------------------------- RequestPolicy
def test_policy_restores_requests_afterwards():
    original = requests.sessions.Session.send
    with cli.RequestPolicy(delay=0.01):
        assert requests.sessions.Session.send is not original
    assert requests.sessions.Session.send is original


def test_policy_restores_requests_after_an_exception():
    original = requests.sessions.Session.send
    with pytest.raises(RuntimeError):
        with cli.RequestPolicy():
            raise RuntimeError("boom")
    assert requests.sessions.Session.send is original


def test_delay_is_enforced_between_requests(serve):
    url = serve(HOME)
    with cli.RequestPolicy(delay=0.15) as policy:
        start = time.monotonic()
        for _ in range(3):
            requests.get(url)
        elapsed = time.monotonic() - start
    assert elapsed >= 0.29  # two pauses of 0.15 s (the first request is not delayed)
    assert policy.sent == 3


def test_timeout_overrides_the_callers_timeout(serve):
    slow = serve({"/": (200, lambda qs: time.sleep(1) or "<html></html>", {})})
    with cli.RequestPolicy(timeout=0.2):
        with pytest.raises(requests.exceptions.ReadTimeout):
            requests.get(slow, timeout=30)


def test_out_of_scope_request_is_blocked_and_recorded(serve):
    url = serve(HOME)
    with cli.RequestPolicy(scope=scope_of("example.com")) as policy:
        with pytest.raises(cli.OutOfScope):
            requests.get(url)
    assert policy.blocked == ["127.0.0.1"]
    assert policy.sent == 0


def test_in_scope_request_goes_through(serve):
    url = serve(HOME)
    with cli.RequestPolicy(scope=scope_of("127.0.0.1")) as policy:
        assert requests.get(url).status_code == 200
    assert policy.sent == 1
    assert policy.blocked == []


def test_redirect_to_an_out_of_scope_host_is_blocked(serve):
    target = serve(HOME).replace("127.0.0.1", "localhost")
    url = serve({"/": (302, "", {"Location": target})})
    with cli.RequestPolicy(scope=scope_of("127.0.0.1")) as policy:
        with pytest.raises(cli.OutOfScope):
            requests.get(url)
    assert policy.blocked == ["localhost"]
    assert policy.sent == 1  # only the first hop left the machine


def test_stop_refuses_any_further_request(serve):
    url = serve(HOME)
    with cli.RequestPolicy() as policy:
        policy.stop()
        with pytest.raises(requests.exceptions.RequestException):
            requests.get(url)


# ---------------------------------------------------------------- command line
def test_target_outside_the_scope_file_is_refused_before_any_request(scope_file, capsys):
    assert cli.main([DEAD, "--yes", "--scope-file", scope_file("example.com")]) == 2
    assert "not in the scope file" in capsys.readouterr().out


def test_missing_or_empty_scope_file_is_an_error(tmp_path, scope_file, capsys):
    assert cli.main([DEAD, "--yes", "--scope-file", str(tmp_path / "nope.txt")]) == 2
    assert "Scope file error" in capsys.readouterr().out
    assert cli.main([DEAD, "--yes", "--scope-file", scope_file("# nothing")]) == 2
    assert "Scope file error" in capsys.readouterr().out


def test_scan_inside_the_scope_reports_its_settings_in_json(serve, scope_file, capsys):
    argv = [serve(ADMIN), "--yes", "--json", "--scope-file", scope_file("127.0.0.1"),
            "--delay", "0", "--timeout", "5"]
    assert cli.main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["settings"] == {"delay": 0.0, "timeout": 5.0, "scope_file": "scope.txt"}
    assert report["requests_sent"] > 0
    assert report["blocked_hosts"] == []


def test_redirect_out_of_scope_stops_the_scan(serve, scope_file, capsys):
    target = serve(ADMIN).replace("127.0.0.1", "localhost")
    url = serve({"/": (302, "", {"Location": target})})
    assert cli.main([url, "--yes", "--scope-file", scope_file("127.0.0.1")]) == 2
    assert "not in the scope file" in capsys.readouterr().out


def test_form_posting_to_an_out_of_scope_host_is_blocked(serve, scope_file, capsys):
    hits = []
    other = serve({"/search": (200, lambda qs: hits.append(qs) or "<html></html>", {})})
    other = other.replace("127.0.0.1", "localhost")
    form = f'<html><form action="{other}/search" method="get"><input name="query"></form></html>'
    url = serve({"/": (200, form, {})})
    assert cli.main([url, "--yes", "--json", "--scope-file", scope_file("127.0.0.1")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["blocked_hosts"] == ["localhost"]
    assert hits == []  # nothing was ever sent to the out-of-scope host


def test_delay_flag_slows_the_scan_down(serve, capsys):
    start = time.monotonic()
    assert cli.main([serve(HOME), "--yes", "--json", "--delay", "0.05"]) == 0
    elapsed = time.monotonic() - start
    report = json.loads(capsys.readouterr().out)
    assert elapsed >= (report["requests_sent"] - 1) * 0.05 * 0.9


def test_timeout_flag_stops_a_slow_target(serve, capsys):
    slow = serve({"/": (200, lambda qs: time.sleep(1) or "<html></html>", {})})
    assert cli.main([slow, "--yes", "-q", "--timeout", "0.2"]) == 2
    assert "timed out" in capsys.readouterr().out.lower()


@pytest.mark.parametrize("flag, value", [
    ("--delay", "-1"), ("--delay", "abc"), ("--delay", "nan"),
    ("--timeout", "0"), ("--timeout", "-3"), ("--timeout", "inf"),
])
def test_invalid_numeric_options_are_rejected(flag, value):
    with pytest.raises(SystemExit) as exc:
        cli.main([DEAD, flag, value])
    assert exc.value.code == 2
