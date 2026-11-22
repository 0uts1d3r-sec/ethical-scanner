#!/usr/bin/env python3
"""
EthicalScanner CLI
Command-line front end for the EthicalScanner engine (no Tk required).
For authorized security testing only.
"""

import argparse
import json
import os
import re
import sys
import threading
from datetime import datetime
from html import escape
from urllib.parse import urlparse

import requests

import ethical_scanner as core

__version__ = "1.0.0"

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
FAIL_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Payload keywords that modify or destroy data: they need an explicit opt-in.
DESTRUCTIVE_RE = re.compile(
    r"\b(drop|delete|insert|update|truncate|alter|exec|shutdown)\b", re.IGNORECASE)

ANSI = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
        "red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m",
        "cyan": "\033[36m"}
LOG_STYLE = {"info": "dim", "ok": "green", "warn": "yellow", "vuln": "red"}
SEV_STYLE = {"Critical": "red", "High": "red", "Medium": "yellow", "Low": "dim"}


class Output:
    """Thread-safe printing with optional colors."""

    def __init__(self, color, stream):
        self.color = color
        self.stream = stream
        self.lock = threading.Lock()

    def paint(self, text, *styles):
        if not self.color or not styles:
            return text
        return "".join(ANSI[s] for s in styles) + text + ANSI["reset"]

    def line(self, text="", *styles):
        with self.lock:
            print(self.paint(text, *styles), file=self.stream, flush=True)


# ------------------------------------------------------------------ helpers
def sort_key(vuln):
    return (-SEVERITY_ORDER.get(vuln["severity"], 0), vuln["type"])


def count_by_severity(results):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in results:
        if v["severity"] in counts:
            counts[v["severity"]] += 1
    return counts


def describe_wordlist(manager, kind):
    path = getattr(manager, f"{kind}_file")
    payloads = getattr(manager, f"{kind}_payloads")
    name = os.path.basename(path) if path else "Default"
    return f"{name} ({len(payloads)} payloads)"


def report_name(url, ext):
    host = re.sub(r"[^A-Za-z0-9_-]+", "_", urlparse(url).netloc) or "target"
    return f"report_{host}_{datetime.now().strftime('%Y%m%d_%H%M')}.{ext}"


def normalize_url(raw):
    url = raw.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    if not urlparse(url).netloc:
        raise ValueError(f"Invalid URL: {raw!r}")
    return url


def confirm_authorization(host, assume_yes, out):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        out.line("Non-interactive session: pass --yes to confirm that you are "
                 "authorized to test this target.", "red")
        return False
    out.line(f"You are about to actively test {host}.", "bold")
    answer = input("Do you have explicit authorization (program scope or written "
                   "permission)? [y/N] ")
    return answer.strip().lower() in ("y", "yes")


def check_reachable(url, out):
    """Stop early on a dead target instead of reporting misleading findings."""
    try:
        requests.get(url, timeout=10, verify=False,
                     headers={"User-Agent": "EthicalScanner"})
        return True
    except requests.exceptions.RequestException as e:
        out.line(f"Target unreachable: {core.short_error(e)}", "red")
        out.line(f"Nothing answered at {url}. Check the address, the port and "
                 "that the service is running.", "red")
        return False


# ------------------------------------------------------------------ reports
def build_json(url, results, cms, sql_src, xss_src):
    return json.dumps({
        "tool": "EthicalScanner CLI",
        "version": __version__,
        "target": url,
        "date": datetime.now().isoformat(timespec="seconds"),
        "wordlists": {"sqli": sql_src, "xss": xss_src},
        "summary": count_by_severity(results),
        "findings": sorted(results, key=sort_key),
        "cms": [{k: c[k] for k in ("name", "confidence", "evidence", "known_vulns")}
                for c in cms],
    }, indent=2, ensure_ascii=False)


def build_text(url, results, cms, sql_src, xss_src, verbose=True):
    counts = count_by_severity(results)
    lines = [f"Target : {url}",
             f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
             f"Lists  : SQLi: {sql_src} | XSS: {xss_src}", ""]
    if not results:
        lines.append("No findings.")
    for v in sorted(results, key=sort_key):
        lines.append(f"[{v['severity'].upper():<8}] {v['type']}: {v['description']}")
        if verbose and v.get("detail"):
            lines.append(f"{'':11}{v['detail']}")
    if cms:
        lines += ["", "CMS detected: " + ", ".join(
            f"{c['name']} ({c['confidence']}%)" for c in cms)]
    lines += ["", "Summary: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n)
              if results else "Summary: clean"]
    return "\n".join(lines) + "\n"


def build_html(url, results, cms, sql_src, xss_src):
    counts = count_by_severity(results)
    rows = "".join(
        f"<tr class=\"sev-{escape(v['severity'].lower())}\"><td>{escape(v['severity'])}</td>"
        f"<td>{escape(v['type'])}</td><td>{escape(v['description'])}</td>"
        f"<td>{escape(v.get('detail', ''))}</td></tr>"
        for v in sorted(results, key=sort_key)) or \
        "<tr><td colspan=\"4\">No findings.</td></tr>"
    cms_rows = "".join(
        f"<li><strong>{escape(c['name'])}</strong> ({c['confidence']}%): "
        f"{escape('; '.join(c['evidence']))}</li>" for c in cms)
    badges = "".join(f"<span class=\"badge\">{n} {s}</span>"
                     for s, n in counts.items() if n)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EthicalScanner report - {escape(urlparse(url).netloc)}</title>
<style>
:root{{--bg:#fff;--fg:#14161a;--dim:#5b616b;--line:#d9dde3;--head:#eef1f5}}
@media (prefers-color-scheme: dark){{:root{{--bg:#0a0a0b;--fg:#f8fbff;--dim:#9aa0a8;--line:#2e3036;--head:#1c1e22}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:2rem}}
h1{{font-size:1.4rem;margin:0 0 .25rem}} .meta{{color:var(--dim);margin-bottom:1rem}}
.badge{{border:1px solid var(--line);border-radius:4px;padding:2px 8px;margin-right:6px}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border-bottom:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}}
th{{background:var(--head)}} .sev-high td:first-child,.sev-critical td:first-child{{font-weight:700}}
.sev-low td{{color:var(--dim)}}
</style></head><body>
<h1>EthicalScanner report</h1>
<div class="meta">{escape(url)} | {datetime.now().strftime('%Y-%m-%d %H:%M')} |
SQLi: {escape(sql_src)} | XSS: {escape(xss_src)}</div>
<div>{badges or '<span class="badge">clean</span>'}</div>
<div class="wrap"><table><thead><tr><th>Severity</th><th>Type</th><th>Description</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table></div>
{('<h2>CMS detected</h2><ul>' + cms_rows + '</ul>') if cms else ''}
<p class="meta">For authorized security testing only.</p>
</body></html>
"""


def write_report(path, url, results, cms, manager, out):
    ext = os.path.splitext(path)[1].lower()
    sql_src, xss_src = describe_wordlist(manager, "sql"), describe_wordlist(manager, "xss")
    if ext == ".pdf":
        if not core.PDF_AVAILABLE:
            raise RuntimeError("PDF export needs ReportLab: pip install reportlab")
        core.PDFReportGenerator(url, results, path, sql_source=sql_src,
                                xss_source=xss_src).generate()
    else:
        builders = {".json": build_json, ".html": build_html, ".htm": build_html,
                    ".txt": build_text, ".md": build_text}
        if ext not in builders:
            raise RuntimeError(f"Unsupported report extension {ext!r} "
                               "(use .json, .html, .pdf or .txt)")
        with open(path, "w", encoding="utf-8") as f:
            f.write(builders[ext](url, results, cms, sql_src, xss_src))
    out.line(f"Report saved: {path}", "green")


# ------------------------------------------------------------------ CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="ethical_scanner_cli.py",
        description="Command-line web vulnerability scanner. "
                    "For authorized security testing only.",
        epilog="Tip: sites without HTTPS need an explicit http:// URL.")
    p.add_argument("url", help="target URL (https:// is assumed when no scheme is given)")
    p.add_argument("--sqli-wordlist", metavar="FILE", help="custom SQLi payloads (.txt)")
    p.add_argument("--xss-wordlist", metavar="FILE", help="custom XSS payloads (.txt)")
    p.add_argument("--allow-destructive", action="store_true",
                   help="allow SQLi payloads that modify or delete data "
                        "(lab databases only)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="save a report; format from extension (.json .html .pdf .txt)")
    p.add_argument("--json", action="store_true",
                   help="print the JSON report on stdout (logs go to stderr)")
    p.add_argument("--fail-on", choices=sorted(FAIL_LEVELS), metavar="LEVEL",
                   help="exit with code 1 if a finding of this level or higher "
                        "exists (low, medium, high, critical)")
    p.add_argument("-q", "--quiet", action="store_true", help="hide the live log")
    p.add_argument("--no-color", action="store_true", help="disable colors")
    p.add_argument("-y", "--yes", action="store_true",
                   help="confirm that you are authorized to test the target")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def load_wordlists(args, out):
    manager = core.WordlistManager()
    for kind, path in (("sql", args.sqli_wordlist), ("xss", args.xss_wordlist)):
        if not path:
            continue
        ok, error, count = getattr(manager, f"apply_{kind}")(path)
        if not ok:
            out.line(f"{kind.upper()} wordlist error: {error}", "red")
            return None
        out.line(f"{kind.upper()} wordlist: {os.path.basename(path)} ({count} payloads)", "dim")
    if any(DESTRUCTIVE_RE.search(p) for p in manager.sql_payloads) \
            and not args.allow_destructive:
        out.line("This SQLi wordlist contains payloads that can modify or delete data.", "red")
        out.line("Use it only on a disposable lab database you own, then add "
                 "--allow-destructive.", "red")
        return None
    return manager


def main(argv=None):
    args = build_parser().parse_args(argv)
    use_color = (not args.no_color and "NO_COLOR" not in os.environ
                 and sys.stdout.isatty())
    log_stream = sys.stderr if args.json else sys.stdout
    out = Output(use_color and log_stream.isatty(), log_stream)

    try:
        url = normalize_url(args.url)
    except ValueError as e:
        out.line(str(e), "red")
        return 2

    out.line(f"EthicalScanner CLI v{__version__} | for authorized testing only", "bold")
    manager = load_wordlists(args, out)
    if manager is None:
        return 2
    if not confirm_authorization(urlparse(url).netloc, args.yes, out):
        out.line("Aborted: authorization not confirmed.", "red")
        return 2
    if not check_reachable(url, out):
        return 2

    def on_log(msg, kind="info"):
        if not args.quiet:
            out.line(msg, LOG_STYLE.get(kind))

    finished = threading.Event()
    engine = core.ScanEngine(
        url, manager.sql_payloads, manager.xss_payloads,
        log_callback=on_log, vuln_callback=lambda v: None,
        cms_callback=lambda c: None,
        done_callback=lambda results, cms: finished.set())

    out.line(f"=== SCAN: {engine.url} ===", "bold")
    engine.start()
    interrupted = False
    try:
        while not finished.wait(0.2):
            pass
    except KeyboardInterrupt:
        interrupted = True
        out.line("\nInterrupted: showing partial results.", "yellow")

    results, cms = list(engine.results), list(engine.detected_cms)
    sql_src, xss_src = describe_wordlist(manager, "sql"), describe_wordlist(manager, "xss")

    if args.json:
        print(build_json(engine.url, results, cms, sql_src, xss_src))
    else:
        out.line()
        for v in sorted(results, key=sort_key):
            tag = f"[{v['severity'].upper():<8}]"
            out.line(f"{tag} {v['type']}: {v['description']}", SEV_STYLE.get(v["severity"]))
        counts = count_by_severity(results)
        summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "clean"
        out.line(f"=== DONE: {len(results)} finding(s) | {len(cms)} CMS | {summary} ===", "bold")

    if args.output:
        try:
            write_report(args.output, engine.url, results, cms, manager, out)
        except (RuntimeError, OSError) as e:
            out.line(f"Report error: {e}", "red")
            return 2

    if interrupted:
        return 130
    if args.fail_on:
        threshold = FAIL_LEVELS[args.fail_on]
        if any(SEVERITY_ORDER.get(v["severity"], 0) >= threshold for v in results):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
