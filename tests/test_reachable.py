"""check_reachable: the target must answer before anything is scanned."""
import time

import pytest

import ethical_scanner as core

DEAD = "http://127.0.0.1:9"  # nothing listens here
HOME = {"/": (200, "<html></html>", {})}
SLOW = {"/": (200, lambda qs: time.sleep(1) or "<html></html>", {})}


def test_a_target_that_answers_is_reachable(serve):
    assert core.check_reachable(serve(HOME)) == (True, None)


def test_an_error_page_still_counts_as_reachable(serve):
    ok, message = core.check_reachable(serve({"/": (500, "boom", {})}))
    assert ok and message is None


def test_a_dead_target_gives_a_short_message():
    ok, message = core.check_reachable(DEAD)
    assert not ok
    assert message == "Target unreachable: Could not connect to the target"


def test_a_slow_target_times_out(serve):
    ok, message = core.check_reachable(serve(SLOW), timeout=0.2)
    assert not ok and "timed out" in message.lower()


def test_the_policy_timeout_applies_to_the_check(serve):
    with core.RequestPolicy(timeout=0.2):
        ok, message = core.check_reachable(serve(SLOW), timeout=30)
    assert not ok and "timed out" in message.lower()


def test_a_redirect_leaving_the_scope_is_reported(serve):
    target = serve(HOME).replace("127.0.0.1", "localhost")
    url = serve({"/": (302, "", {"Location": target})})
    scope = core.Scope(["127.0.0.1"], "scope.txt")
    with core.RequestPolicy(scope=scope):
        ok, message = core.check_reachable(url)
    assert not ok and "not in the scope file" in message


def test_a_stopped_policy_refuses_the_check(serve):
    with core.RequestPolicy() as policy:
        policy.stop()
        ok, message = core.check_reachable(serve(HOME))
    assert not ok and "stopped" in message.lower()
