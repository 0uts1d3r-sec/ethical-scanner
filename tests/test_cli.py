"""Command-line front end: safeguards, exit codes and reports."""
import ast
import io
import json
import subprocess
import sys

import pytest

import ethical_scanner as core
import ethical_scanner_cli as cli
from conftest import ROOT

DEAD = "http://127.0.0.1:9"  # nothing listens here
ADMIN = {"/": (200, "<html></html>", {}), "/admin": (200, "ok", {})}


def test_engine_imports_without_tkinter():
    code = (
        "import sys; sys.modules['tkinter'] = None;"
        "import ethical_scanner as c; assert c.GUI_AVAILABLE is False"
    )
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)


def test_destructive_wordlist_needs_explicit_opt_in(capsys):
    path = str(ROOT / "wordlists" / "sqli_destructive.txt")
    assert cli.main([DEAD, "--yes", "--sqli-wordlist", path]) == 2
    assert "--allow-destructive" in capsys.readouterr().out


def test_sample_wordlists_pass_the_destructive_gate():
    args = cli.build_parser().parse_args(
        [DEAD, "--sqli-wordlist", str(ROOT / "wordlists" / "sqli_samples.txt")]
    )
    assert cli.load_wordlists(args, cli.Output(False, io.StringIO())) is not None


def test_authorization_is_required_when_non_interactive(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main([DEAD]) == 2
    assert "authorization not confirmed" in capsys.readouterr().out


def test_unreachable_target_stops_and_writes_no_report(tmp_path):
    report = tmp_path / "r.json"
    assert cli.main([DEAD, "--yes", "-o", str(report)]) == 2
    assert not report.exists()


def test_invalid_url_is_rejected():
    assert cli.main(["http://", "--yes"]) == 2


def test_fail_on_sets_the_exit_code(serve):
    url = serve(ADMIN)
    assert cli.main([url, "--yes", "-q", "--no-color", "--fail-on", "high"]) == 1
    assert cli.main([url, "--yes", "-q", "--no-color", "--fail-on", "critical"]) == 0


def test_json_goes_to_stdout_and_logs_to_stderr(serve, capsys):
    assert cli.main([serve(ADMIN), "--yes", "--json"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert {"target", "summary", "findings", "cms", "wordlists"} <= report.keys()
    assert report["summary"]["High"] >= 1
    assert "=== SCAN" in captured.err


@pytest.mark.parametrize("ext", ["json", "html", "txt", "pdf"])
def test_report_formats_are_written(serve, tmp_path, ext):
    if ext == "pdf" and not core.PDF_AVAILABLE:
        pytest.skip("reportlab not installed")
    report = tmp_path / f"r.{ext}"
    assert cli.main([serve(ADMIN), "--yes", "-q", "--no-color", "-o", str(report)]) == 0
    assert report.stat().st_size > 0


def test_unsupported_report_extension_is_an_error(serve, tmp_path):
    assert cli.main([serve(ADMIN), "--yes", "-q", "-o", str(tmp_path / "r.xyz")]) == 2


def test_html_report_escapes_scan_content():
    finding = {"type": "<script>alert(1)</script>", "severity": "High",
               "description": "<img src=x onerror=alert(1)>", "detail": "\"quoted\""}
    html = cli.build_html("http://t", [finding], [], "Default", "Default")
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


FORM = '<html><form action="/search" method="get"><input name="query"></form></html>'
FORM_SITE = {
    "/": (200, FORM, {}),
    "/search": (200, lambda qs: "<html>" + qs.get("query", [""])[0] + "</html>", {}),
}


class FakeTTY(io.StringIO):
    """A stdout that claims to be a terminal, so the CLI turns colors on."""

    def isatty(self):
        return True


def engine_log_kinds():
    """Every log type that ScanEngine can emit, read from the source (format-proof)."""
    tree = ast.parse((ROOT / "ethical_scanner.py").read_text(encoding="utf-8"))
    return {
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "log"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
    }


def test_every_engine_log_type_has_a_style():
    assert engine_log_kinds() <= set(cli.LOG_STYLE)


def test_unknown_or_missing_style_never_crashes_with_colors_on():
    out = cli.Output(True, io.StringIO())
    out.line("hello", "no-such-style")
    out.line("hello", None)
    out.line("hello")


def test_form_scan_is_not_aborted_when_colors_are_on(serve, monkeypatch):
    tty = FakeTTY()
    monkeypatch.setattr(sys, "stdout", tty)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert cli.main([serve(FORM_SITE), "--yes"]) == 0
    text = tty.getvalue()
    assert "\x1b[" in text  # colors really were on
    assert "Form scan error" not in text
    assert "Reflected XSS" in text


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
