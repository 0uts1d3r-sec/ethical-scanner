"""build_request_policy: the limits typed in the GUI (no Tk needed)."""
import pytest

import ethical_scanner as core


@pytest.fixture
def scope_file(tmp_path):
    def make(*lines):
        path = tmp_path / "scope.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    return make


def test_no_limits_gives_a_neutral_policy():
    policy, error = core.build_request_policy("http://example.com")
    assert error is None
    assert (policy.scope, policy.delay, policy.timeout) == (None, 0.0, None)


def test_delay_and_timeout_are_parsed_and_accept_a_decimal_comma():
    policy, error = core.build_request_policy("http://a.com", None, "0,5", " 7 ")
    assert error is None
    assert (policy.delay, policy.timeout) == (0.5, 7.0)


@pytest.mark.parametrize("delay", ["abc", "-1", "nan", "inf"])
def test_invalid_delay_is_refused(delay):
    policy, error = core.build_request_policy("http://a.com", None, delay, "")
    assert policy is None and error.startswith("Delay")


@pytest.mark.parametrize("timeout", ["abc", "0", "-2", "inf"])
def test_invalid_timeout_is_refused(timeout):
    policy, error = core.build_request_policy("http://a.com", None, "0", timeout)
    assert policy is None and error.startswith("Timeout")


def test_target_inside_the_scope_is_accepted(scope_file):
    policy, error = core.build_request_policy("https://app.example.com/x", scope_file("*.example.com"))
    assert error is None and policy.scope.source == "scope.txt"


def test_target_outside_the_scope_is_refused(scope_file):
    policy, error = core.build_request_policy("https://evil.test", scope_file("example.com"))
    assert policy is None
    assert "evil.test" in error and "not in the scope file" in error


def test_missing_or_empty_scope_file_is_an_error(tmp_path, scope_file):
    _, error = core.build_request_policy("http://a.com", str(tmp_path / "nope.txt"))
    assert error.startswith("Scope file error")
    _, error = core.build_request_policy("http://a.com", scope_file("# nothing"))
    assert error.startswith("Scope file error")


def test_policy_can_be_activated_and_deactivated_manually():
    import requests

    original = requests.sessions.Session.send
    policy = core.RequestPolicy()
    policy.activate()
    policy.activate()  # a second call changes nothing
    assert requests.sessions.Session.send is not original
    policy.deactivate()
    policy.deactivate()
    assert requests.sessions.Session.send is original
