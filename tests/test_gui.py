"""The real Tk interface, run under a virtual display (xvfb-run in CI).
These tests are skipped when Tk or a display is not available."""
import gc
import time

import pytest
import requests

import ethical_scanner as core

pytest.importorskip("tkinter")

FORM_PAGE = '<html><form action="{action}" method="get"><input name="query"></form></html>'


@pytest.fixture
def app(monkeypatch):
    try:
        window = core.ScannerApp()
    except Exception as exc:  # no display: tkinter.TclError
        pytest.skip(f"no usable display: {exc}")
    warnings = []
    monkeypatch.setattr(core.messagebox, "showwarning", lambda title, msg: warnings.append(msg))
    window.warnings = warnings
    window.withdraw()
    yield window
    window._end_policy()  # never leave the request limits installed
    window.destroy()
    del window
    # Free the destroyed window's Tk objects here, in the main thread.
    gc.collect()


def fill(entry, text):
    entry.delete(0, "end")
    entry.insert(0, text)


def run_scan(app, url, scope=None, delay="0", timeout=""):
    fill(app.url_field, url)
    fill(app.delay_entry, delay)
    fill(app.timeout_entry, timeout)
    app.scope_path = scope
    app.start_scan()
    # Like the real application, run a main loop: the engine thread talks to Tk
    # through after(), which requires the main thread to be inside mainloop().
    deadline = time.time() + 60

    def poll():
        if not app.scan_running or time.time() > deadline:
            app.quit()
        else:
            app.after(30, poll)

    app.after(30, poll)
    app.mainloop()
    app.after(200, app.quit)  # let the queued log lines through
    app.mainloop()
    assert not app.scan_running, "the scan did not finish"


def log_text(app):
    return app.log_area.get("1.0", "end")


def test_limits_bar_exists_with_sane_defaults(app):
    assert app.delay_entry.get() == "0"
    assert app.timeout_entry.get() == ""
    assert app.scope_label.cget("text") == "none (any target)"


def test_scan_with_limits_logs_them_and_restores_requests(app, serve, tmp_path):
    original = requests.sessions.Session.send
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    url = serve({"/": (200, "<html></html>", {}), "/admin": (200, "ok", {})})
    run_scan(app, url, str(scope), delay="0.01", timeout="5")
    text = log_text(app)
    assert "Scope: scope.txt" in text
    assert "Delay: 0.01 s" in text and "Timeout: 5 s" in text
    assert "Requests sent:" in text
    assert any(v["type"] == "Exposed path" for v in app.scan_results)
    assert requests.sessions.Session.send is original
    assert app.policy is None


def test_target_outside_the_scope_is_refused_before_scanning(app, serve, tmp_path):
    original = requests.sessions.Session.send
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n")
    app.url_field.delete(0, "end")
    app.url_field.insert(0, serve({"/": (200, "<html></html>", {})}))
    app.scope_path = str(scope)
    app.start_scan()
    assert not app.scan_running
    assert app.warnings and "not in the scope file" in app.warnings[0]
    assert requests.sessions.Session.send is original


@pytest.mark.parametrize("field, value", [("delay", "-1"), ("delay", "abc"), ("timeout", "0")])
def test_invalid_limits_are_refused_with_a_message(app, serve, field, value):
    app.url_field.delete(0, "end")
    app.url_field.insert(0, serve({"/": (200, "<html></html>", {})}))
    fill(app.delay_entry if field == "delay" else app.timeout_entry, value)
    app.start_scan()
    assert not app.scan_running
    assert app.warnings and field.capitalize() in app.warnings[0]


def test_form_posting_to_an_out_of_scope_host_is_blocked(app, serve, tmp_path):
    hits = []
    other = serve({"/search": (200, lambda qs: hits.append(qs) or "<html></html>", {})})
    other = other.replace("127.0.0.1", "localhost")
    url = serve({"/": (200, FORM_PAGE.format(action=f"{other}/search"), {})})
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    run_scan(app, url, str(scope))
    assert "Blocked out-of-scope host(s): localhost" in log_text(app)
    assert hits == []  # nothing ever reached the out-of-scope host


def test_clear_scope_resets_the_label(app, tmp_path):
    app.scope_path = str(tmp_path / "x.txt")
    app.scope_label.config(text="x.txt")
    app._clear_scope()
    assert app.scope_path is None
    assert app.scope_label.cget("text") == "none (any target)"
