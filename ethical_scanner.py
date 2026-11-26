"""
WEB VULNERABILITY SCANNER
Wordlist loading (SQLi + XSS from .txt files)
For authorized security testing only!
"""

import requests
import time
import math
import ipaddress
import sys
import threading
import re
import os
from html import escape
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import webbrowser

try:                                    # Tk is optional: the CLI works without it
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    GUI_AVAILABLE = True
except ImportError:
    tk = None
    GUI_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency. Run: pip install beautifulsoup4")
    sys.exit(1)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph,
        Spacer,
        HRFlowable,
    )
    from reportlab.lib.enums import TA_CENTER

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Folder shipped with the project that contains the sample wordlists
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")


#  THEME
#  One soft accent (sky blue) on black, with slate-blue panels. Header and borders are
#  the accent mixed into black; text is a cool off-white, never pure white.
ACCENT = "#F8FBFF"  # titles, primary button, highlights
PRIMARY = "#1A1B1E"  # header band, table headers, secondary buttons
TEXT = "#F8FBFF"  # main text
TEXT_DIM = "#9AA0A8"  # secondary text
INK = "#0A0A0B"  # status bar, text on the accent button

BG = "#0A0A0B"  # app background
SURFACE = "#131416"  # log, tables, previews (mid-tone: needs dark text)
SURFACE_HI = "#1C1E22"  # inputs, cards
BORDER = "#2E3036"  # separators, outlines
MUTED = "#5F646B"  # disabled controls only

# Text drawn ON the mid-tone SURFACE (light text would be unreadable there)
ON_SURFACE = "#D5DAE0"  # main text
ON_SURFACE_DIM = "#8E949C"  # secondary text
ON_SURFACE_HI = "#F8FBFF"  # emphasis (findings, titles)


#  DEFAULT PAYLOADS (used when no wordlist is loaded)
DEFAULT_SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    '" OR "1"="1',
    "' UNION SELECT NULL--",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "' AND 1=2 UNION SELECT 1,2,3--",
]

DEFAULT_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "\"><img src=x onerror=alert('XSS')>",
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "pg_query",
    "sqlite3.operationalerror",
    "ora-01756",
    "microsoft ole db provider",
    "odbc sql server driver",
]

SENSITIVE_PATHS = [
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/backup",
    "/config",
    "/api/users",
    "/robots.txt",
    "/.htaccess",
    "/wp-config.php",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
]


#  WORDLIST MANAGER
class WordlistManager:
    """
    Handles loading, validating and previewing wordlist (.txt)
    files for SQLi and XSS payloads.

    .txt file format:
    - One entry per line
    - Lines starting with # are comments
    - Blank lines are ignored
    """

    def __init__(self):
        # Active payloads (start with the default values)
        self.sql_payloads = list(DEFAULT_SQL_PAYLOADS)
        self.xss_payloads = list(DEFAULT_XSS_PAYLOADS)

        # Paths of the loaded files
        self.sql_file = None
        self.xss_file = None

    def load_file(self, file_path):
        """
        Reads a .txt file and returns the list of payloads.
        Ignores comments (#) and blank lines.
        Returns (payload_list, nb_loaded, nb_skipped, error)
        """
        if not file_path or not os.path.exists(file_path):
            return [], 0, 0, "File not found"

        if not file_path.lower().endswith(".txt"):
            return [], 0, 0, "The file must be a .txt"

        payloads = []
        nb_skipped = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()

                # Skip blank lines and comments
                if not line or line.startswith("#"):
                    nb_skipped += 1
                    continue

                # Skip if too long (safety)
                if len(line) > 500:
                    nb_skipped += 1
                    continue

                payloads.append(line)

            if not payloads:
                return [], 0, nb_skipped, "No valid payload found in the file"

            return payloads, len(payloads), nb_skipped, None

        except PermissionError:
            return [], 0, 0, "Permission denied reading this file"
        except Exception as e:
            return [], 0, 0, f"Read error: {e}"

    def apply_sql(self, file_path):
        """Loads a wordlist file and applies it to the SQLi payloads."""
        payloads, nb, skipped, error = self.load_file(file_path)
        if error:
            return False, error, 0
        self.sql_payloads = payloads
        self.sql_file = file_path
        return True, None, nb

    def apply_xss(self, file_path):
        """Loads a wordlist file and applies it to the XSS payloads."""
        payloads, nb, skipped, error = self.load_file(file_path)
        if error:
            return False, error, 0
        self.xss_payloads = payloads
        self.xss_file = file_path
        return True, None, nb

    def reset_sql(self):
        """Restores the default SQLi payloads."""
        self.sql_payloads = list(DEFAULT_SQL_PAYLOADS)
        self.sql_file = None

    def reset_xss(self):
        """Restores the default XSS payloads."""
        self.xss_payloads = list(DEFAULT_XSS_PAYLOADS)
        self.xss_file = None


#  CMS KNOWLEDGE BASE
CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
        "headers": [],
        "cookies": ["wordpress_", "wp-settings-"],
        "html_patterns": [
            r'<meta name="generator" content="WordPress',
            r"/wp-content/themes/",
            r"wp-emoji",
        ],
        "known_vulns": [
            "Check for vulnerable plugins via WPScan",
            "Keep WordPress up to date",
            "Protect wp-login.php with 2FA",
            "Disable user enumeration (?author=1)",
        ],
        "icon": "[WP]",
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/"],
        "headers": [],
        "cookies": ["joomla_"],
        "html_patterns": [
            r'<meta name="generator" content="Joomla',
            r"/media/jui/",
            r"option=com_",
        ],
        "known_vulns": [
            "Keep Joomla up to date",
            "Check third-party extensions",
            "Protect /administrator/ by IP",
        ],
        "icon": "[JM]",
    },
    "Drupal": {
        "paths": ["/user/login", "/core/", "/sites/default/"],
        "headers": ["X-Generator: Drupal"],
        "cookies": ["SESS"],
        "html_patterns": [
            r'<meta name="Generator" content="Drupal',
            r"Drupal\.settings",
        ],
        "known_vulns": ["Keep Drupal up to date", "Check /sites/default/settings.php"],
        "icon": "[DR]",
    },
    "Magento": {
        "paths": ["/admin/", "/skin/frontend/"],
        "headers": [],
        "cookies": ["frontend"],
        "html_patterns": [r"Mage\.Cookies", r"/skin/frontend/"],
        "known_vulns": [
            "Magento is a frequent skimming target",
            "Upgrade to Magento 2.x",
        ],
        "icon": "[MG]",
    },
    "Laravel": {
        "paths": ["/public/", "/_ignition/"],
        "headers": [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "html_patterns": [r"csrf-token"],
        "known_vulns": [
            "Never leave APP_DEBUG=true in production",
            "Check that .env is not publicly accessible",
        ],
        "icon": "[LV]",
    },
}


#  SCAN ENGINE (receives the wordlists)
# A CMS is only reported when at least this many independent signals match
# (path, header, cookie, HTML pattern): one generic hit such as /admin/ is not enough.
MIN_CMS_SCORE = 2


class OutOfScope(requests.exceptions.RequestException):
    """Raised when a request would leave the allowed scope."""


class Scope:
    """Allowed targets read from a text file, one entry per line:
    a host (example.com), subdomains only (*.example.com), an IP or a CIDR range."""

    def __init__(self, lines, source="scope"):
        self.source = source
        self.hosts, self.suffixes, self.networks = set(), [], []
        for raw in lines:
            entry = raw.split("#", 1)[0].strip().lower()
            if not entry:
                continue
            if "://" in entry:  # tolerate a pasted URL
                entry = urlparse(entry).hostname or ""
            if entry.startswith("*."):
                self.suffixes.append(entry[1:])  # ".example.com"
                continue
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                if ":" in entry:  # drop a port: host:8443
                    entry = entry.rsplit(":", 1)[0]
                if entry:
                    self.hosts.add(entry.rstrip("."))
        if not (self.hosts or self.suffixes or self.networks):
            raise ValueError("the scope file has no entries")

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls(f.read().splitlines(), os.path.basename(path))

    def allows(self, host):
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if host in self.hosts or any(host.endswith(s) for s in self.suffixes):
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in self.networks)


class RequestPolicy:
    """While active, every HTTP request (redirect hops included) passes through
    Session.send: it enforces the scope, waits `delay` seconds between requests and
    applies a fixed timeout. The scan engine itself needs no change.

    Use it as a context manager, or call activate() / deactivate() yourself."""

    def __init__(self, scope=None, delay=0.0, timeout=None):
        self.scope, self.delay, self.timeout = scope, delay, timeout
        self.sent = 0
        self.blocked = []
        self.stopped = False
        self._last = None
        self._lock = threading.Lock()
        self._original = None

    def activate(self):
        if self._original is not None:
            return self
        policy = self
        self._original = original = requests.sessions.Session.send

        def send(session, request, **kwargs):
            policy._before(request.url)
            if policy.timeout is not None:
                kwargs["timeout"] = policy.timeout
            return original(session, request, **kwargs)

        requests.sessions.Session.send = send
        return self

    def deactivate(self):
        if self._original is not None:
            requests.sessions.Session.send = self._original
            self._original = None

    def __enter__(self):
        return self.activate()

    def __exit__(self, *exc):
        self.deactivate()
        return False

    def stop(self):
        """Refuse every further request (used after Ctrl+C)."""
        self.stopped = True

    def _before(self, url):
        host = urlparse(url).hostname
        with self._lock:
            if self.stopped:
                raise requests.exceptions.RequestException("Scan stopped")
            if self.scope and not self.scope.allows(host):
                label = host or "(no host)"
                if label not in self.blocked:
                    self.blocked.append(label)
                raise OutOfScope(f"Blocked: {label} is not in the scope file")
            if self._last is not None:
                pause = self.delay - (time.monotonic() - self._last)
                if pause > 0:
                    time.sleep(pause)
            self._last = time.monotonic()
            self.sent += 1


def build_request_policy(url, scope_path=None, delay_text="", timeout_text=""):
    """Check the limits typed in the GUI.
    Returns (policy, None) when they are valid, or (None, error message)."""

    def number(text, name, strict):
        text = (text or "").strip().replace(",", ".")  # accept 0,5 as well as 0.5
        if not text:
            return None, None
        try:
            value = float(text)
        except ValueError:
            return None, f"{name} must be a number of seconds."
        if not math.isfinite(value) or (value <= 0 if strict else value < 0):
            return None, f"{name} must be {'greater than 0' if strict else '0 or more'}."
        return value, None

    delay, error = number(delay_text, "Delay", strict=False)
    if error:
        return None, error
    timeout, error = number(timeout_text, "Timeout", strict=True)
    if error:
        return None, error
    scope = None
    if scope_path:
        try:
            scope = Scope.from_file(scope_path)
        except (OSError, ValueError) as e:
            return None, f"Scope file error: {e}"
        host = urlparse(url).hostname
        if not scope.allows(host):
            return None, f"Target {host} is not in the scope file ({scope.source})."
    return RequestPolicy(scope, delay or 0.0, timeout), None


def check_reachable(url, timeout=10):
    """Ask the target once before scanning.
    Returns (True, None) if it answers, or (False, message).
    It goes through the active RequestPolicy, so the scope and the timeout still apply."""
    try:
        requests.get(
            url, timeout=timeout, verify=False, headers={"User-Agent": "EthicalScanner"}
        )
        return True, None
    except OutOfScope as e:
        return False, str(e)
    except requests.exceptions.RequestException as e:
        return False, f"Target unreachable: {short_error(e)}"


def short_error(e):
    """Turn a long requests/urllib3 exception into a one-line message."""
    msg = str(e)
    low = msg.lower()
    if "ssl" in low or "handshake" in low or "certificate" in low:
        return (
            "TLS/SSL connection failed (the server may not support HTTPS: try http://)"
        )
    if "timed out" in low or "timeout" in low:
        return "Connection timed out"
    if "max retries" in low or "connection" in low or "name or service" in low:
        return "Could not connect to the target"
    return msg[:150]


class ScanEngine(threading.Thread):
    """
    Scan engine run in a separate thread.
    Now receives custom payloads from the WordlistManager.
    """

    def __init__(
        self,
        url,
        sql_payloads,
        xss_payloads,
        log_callback,
        vuln_callback,
        cms_callback,
        done_callback,
    ):
        super().__init__(daemon=True)
        if not url.startswith("http"):
            url = "https://" + url
        self.url = url
        # Customizable payloads
        self.sql_payloads = sql_payloads
        self.xss_payloads = xss_payloads
        self.results = []
        self.detected_cms = []
        self.log = log_callback
        self.add_vuln = vuln_callback
        self.update_cms = cms_callback
        self.finish = done_callback
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalScanner"})

    def record_vuln(self, vuln_type, severity, description, detail=""):
        vuln = {
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "detail": detail,
        }
        self.results.append(vuln)
        self.add_vuln(vuln)

    def test_https(self):
        self.log("Checking HTTPS...", "info")
        if not self.url.startswith("https://"):
            self.record_vuln(
                "Missing HTTPS",
                "High",
                "Site is not encrypted.",
                "Install Let's Encrypt.",
            )
            self.log("  [!] HTTPS missing", "vuln")
        else:
            self.log("  [OK] URL uses HTTPS", "ok")

    def test_headers(self):
        self.log("Checking HTTP headers...", "info")
        try:
            r = self.session.get(self.url, timeout=10, verify=False)
            for h in SECURITY_HEADERS:
                if h not in r.headers:
                    self.record_vuln(
                        f"Header: {h}",
                        "Low",
                        f"'{h}' is missing.",
                        "Configure the server.",
                    )
                    self.log(f"  [!] Missing: {h}", "warn")
                else:
                    self.log(f"  [OK] {h}", "ok")
        except Exception as e:
            self.log(f"  Error: {short_error(e)}", "warn")

    def test_paths(self):
        self.log("Checking sensitive paths...", "info")
        for path in SENSITIVE_PATHS:
            try:
                r = self.session.get(urljoin(self.url, path), timeout=5, verify=False)
                if r.status_code == 200:
                    self.record_vuln(
                        "Exposed path",
                        "High",
                        f"'{path}' is accessible.",
                        f"URL: {urljoin(self.url, path)}",
                    )
                    self.log(f"  [HIT] {path} (200)", "vuln")
                elif r.status_code == 403:
                    self.record_vuln(
                        "Protected path",
                        "Medium",
                        f"'{path}' exists.",
                        f"URL: {urljoin(self.url, path)}",
                    )
                    self.log(f"  [!] {path} (403)", "warn")
            except Exception:
                pass

    def test_forms(self):
        self.log(
            f"Scanning HTML forms ({len(self.sql_payloads)} SQLi payloads, {len(self.xss_payloads)} XSS)...",
            "info",
        )
        try:
            r = self.session.get(self.url, timeout=10, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = []
            for form in soup.find_all("form"):
                action = urljoin(self.url, form.get("action", ""))
                method = form.get("method", "get").lower()
                fields = {
                    inp.get("name"): inp.get("value", "test")
                    for inp in form.find_all(["input", "textarea"])
                    if inp.get("name")
                    and inp.get("type", "text") not in ["submit", "button"]
                }
                if fields:
                    forms.append({"action": action, "method": method, "fields": fields})

            if not forms:
                self.log("  No forms found.", "warn")
                return

            self.log(f"  {len(forms)} form(s) found", "ok")

            for i, form in enumerate(forms):
                self.log(
                    f"  -> Form {i + 1}: {form['method'].upper()} {form['action']}",
                    "scan",
                )

                # -- Test SQLi with the custom wordlist --
                sql_vuln_found = False
                for j, payload in enumerate(self.sql_payloads):
                    if sql_vuln_found:
                        break
                    for field in form["fields"]:
                        data = {**form["fields"], field: payload}
                        try:
                            resp = (
                                self.session.post(
                                    form["action"], data=data, timeout=6, verify=False
                                )
                                if form["method"] == "post"
                                else self.session.get(
                                    form["action"], params=data, timeout=6, verify=False
                                )
                            )
                            if any(
                                e in resp.text.lower() for e in SQL_ERROR_SIGNATURES
                            ):
                                self.record_vuln(
                                    "SQLi (Form)",
                                    "Critical",
                                    f"Field '{field}' is vulnerable to SQL injection.",
                                    f"Payload #{j + 1}: {payload[:80]}",
                                )
                                self.log(
                                    f"  [HIT] SQLi: field '{field}' | payload #{j + 1}",
                                    "vuln",
                                )
                                sql_vuln_found = True
                                break
                        except Exception:
                            pass

                # -- Test XSS with the custom wordlist --
                xss_vuln_found = False
                for j, payload in enumerate(self.xss_payloads):
                    if xss_vuln_found:
                        break
                    for field in form["fields"]:
                        data = {**form["fields"], field: payload}
                        try:
                            resp = (
                                self.session.post(
                                    form["action"], data=data, timeout=6, verify=False
                                )
                                if form["method"] == "post"
                                else self.session.get(
                                    form["action"], params=data, timeout=6, verify=False
                                )
                            )
                            if payload in resp.text:
                                self.record_vuln(
                                    "Reflected XSS (Form)",
                                    "High",
                                    f"Field '{field}' reflects unfiltered code.",
                                    f"Payload #{j + 1}: {payload[:80]}",
                                )
                                self.log(
                                    f"  [HIT] XSS: field '{field}' | payload #{j + 1}",
                                    "vuln",
                                )
                                xss_vuln_found = True
                                break
                        except Exception:
                            pass

        except Exception as e:
            self.log(f"  Form scan error: {short_error(e)}", "warn")

    def detect_cms(self):
        self.log("Detecting CMS...", "info")
        try:
            response = self.session.get(self.url, timeout=10, verify=False)
            html_content = response.text
            response_headers = response.headers
            response_cookies = {c.name: c.value for c in response.cookies}
        except Exception as e:
            self.log(f"  CMS detection error: {short_error(e)}", "warn")
            return

        for cms_name, sig in CMS_SIGNATURES.items():
            score = 0
            evidence = []
            for path in sig["paths"]:
                try:
                    r = self.session.get(
                        urljoin(self.url, path), timeout=5, verify=False
                    )
                    if r.status_code in [200, 301, 302, 403]:
                        score += 1
                        evidence.append(f"Path: {path} ({r.status_code})")
                        break
                except Exception:
                    pass
            for h in sig["headers"]:
                if h.split(":")[0] in response_headers:
                    score += 1
                    evidence.append(f"Header: {h}")
            for c in sig["cookies"]:
                for cn in response_cookies:
                    if c.lower() in cn.lower():
                        score += 1
                        evidence.append(f"Cookie: {cn}")
                        break
            for p in sig["html_patterns"]:
                if re.search(p, html_content, re.IGNORECASE):
                    score += 1
                    evidence.append(f"HTML: {p[:40]}")
                    break

            if 0 < score < MIN_CMS_SCORE:
                self.log(f"  (weak {cms_name} signal ignored: needs {MIN_CMS_SCORE} matches)", "info")
            if score >= MIN_CMS_SCORE:
                self.detected_cms.append(
                    {
                        "name": cms_name,
                        "score": score,
                        "confidence": min(100, score * 25),
                        "evidence": evidence,
                        "known_vulns": sig["known_vulns"],
                        "icon": sig["icon"],
                    }
                )
                self.log(
                    f"  {sig['icon']} {cms_name} detected! ({min(100, score * 25)}%)",
                    "vuln",
                )
                for rec in sig["known_vulns"]:
                    self.record_vuln(
                        f"[{cms_name}] Recommendation",
                        "Medium",
                        rec,
                        f"Detected CMS: {cms_name}",
                    )

        self.update_cms(self.detected_cms)
        if not self.detected_cms:
            self.log("  Unknown or custom CMS", "ok")

    def run(self):
        try:
            self.test_https()
            self.test_headers()
            self.test_paths()
            self.test_forms()
            self.detect_cms()
        except Exception as e:
            self.log(f"Critical error: {e}", "warn")
        finally:
            self.finish(self.results, self.detected_cms)


#  PDF REPORT GENERATOR
class PDFReportGenerator:
    """Builds a PDF report from the scan results using ReportLab."""

    # (background, text) per severity: readable on white paper
    SEVERITY_STYLE = {
        "Critical": (ACCENT, INK),
        "High": (PRIMARY, TEXT),
        "Medium": (TEXT_DIM, INK),
        "Low": (TEXT, INK),
    }

    def __init__(
        self, url, results, output_path, sql_source="Default", xss_source="Default"
    ):
        self.url = url
        self.results = results
        self.output_path = output_path
        self.sql_source = sql_source
        self.xss_source = xss_source

    def generate(self):
        hx = colors.HexColor
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            topMargin=1.5 * cm,
            bottomMargin=1.5 * cm,
            leftMargin=1.5 * cm,
            rightMargin=1.5 * cm,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Title"],
            textColor=hx(PRIMARY),
            alignment=TA_CENTER,
        )
        normal_style = ParagraphStyle(
            "NormalStyle", parent=styles["Normal"], fontSize=9
        )
        heading_style = ParagraphStyle(
            "HeadingStyle", parent=styles["Heading2"], textColor=hx(PRIMARY)
        )
        # Paragraphs ignore table TEXTCOLOR, so each severity gets its own style
        severity_styles = {
            sev: ParagraphStyle(
                f"Sev{sev}",
                parent=normal_style,
                fontName="Helvetica-Bold",
                textColor=hx(fg),
            )
            for sev, (bg, fg) in self.SEVERITY_STYLE.items()
        }

        elements = []
        elements.append(Paragraph("Security Report - EthicalScanner", title_style))
        elements.append(Spacer(1, 0.4 * cm))
        elements.append(HRFlowable(width="100%", thickness=2, color=hx(PRIMARY)))
        elements.append(Spacer(1, 0.4 * cm))

        elements.append(Paragraph(f"<b>Target:</b> {escape(self.url)}", normal_style))
        elements.append(
            Paragraph(
                f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                normal_style,
            )
        )
        elements.append(
            Paragraph(f"<b>SQLi wordlist:</b> {escape(self.sql_source)}", normal_style)
        )
        elements.append(
            Paragraph(f"<b>XSS wordlist:</b> {escape(self.xss_source)}", normal_style)
        )
        elements.append(Spacer(1, 0.5 * cm))

        severities = ["Critical", "High", "Medium", "Low"]
        counts = {sev: 0 for sev in severities}
        for r in self.results:
            if r["severity"] in counts:
                counts[r["severity"]] += 1

        elements.append(Paragraph("Summary", heading_style))
        summary_data = [severities, [str(counts[sev]) for sev in severities]]
        summary_table = Table(summary_data, colWidths=[4 * cm] * 4)
        summary_style = [
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, hx(TEXT_DIM)),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]
        for col, sev in enumerate(severities):
            bg, fg = self.SEVERITY_STYLE[sev]
            summary_style.append(("BACKGROUND", (col, 0), (col, 0), hx(bg)))
            summary_style.append(("TEXTCOLOR", (col, 0), (col, 0), hx(fg)))
        summary_table.setStyle(TableStyle(summary_style))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.6 * cm))

        elements.append(Paragraph("Findings", heading_style))
        elements.append(Spacer(1, 0.2 * cm))

        if not self.results:
            elements.append(Paragraph("No vulnerabilities found.", normal_style))
        else:
            table_data = [["Type", "Severity", "Description", "Detail"]]
            for r in self.results:
                table_data.append(
                    [
                        Paragraph(escape(r["type"]), normal_style),
                        Paragraph(
                            escape(r["severity"]),
                            severity_styles.get(r["severity"], normal_style),
                        ),
                        Paragraph(escape(r["description"]), normal_style),
                        Paragraph(escape(r.get("detail", "")), normal_style),
                    ]
                )
            findings_table = Table(
                table_data, colWidths=[3.5 * cm, 2 * cm, 6 * cm, 5.5 * cm], repeatRows=1
            )
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), hx(PRIMARY)),
                ("TEXTCOLOR", (0, 0), (-1, 0), hx(TEXT)),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, hx(TEXT_DIM)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]
            for i, r in enumerate(self.results, start=1):
                style = self.SEVERITY_STYLE.get(r["severity"])
                if style:
                    style_cmds.append(("BACKGROUND", (1, i), (1, i), hx(style[0])))
            findings_table.setStyle(TableStyle(style_cmds))
            elements.append(findings_table)

        elements.append(Spacer(1, 0.6 * cm))
        elements.append(HRFlowable(width="100%", thickness=2, color=hx(PRIMARY)))
        elements.append(Spacer(1, 0.2 * cm))
        elements.append(
            Paragraph(
                "Confidential report - EthicalScanner - For authorized security testing only.",
                ParagraphStyle(
                    "Footer",
                    parent=styles["Normal"],
                    fontSize=7,
                    textColor=hx(MUTED),
                    alignment=TA_CENTER,
                ),
            )
        )

        doc.build(elements)


#  GRAPHICAL INTERFACE
class ScannerApp(tk.Tk if GUI_AVAILABLE else object):
    def __init__(self):
        super().__init__()
        self.title("EthicalScanner")
        self.geometry("1400x900")
        self.configure(bg=BG)
        self.scan_running = False
        self.scan_results = []
        self.scanned_cms = []
        self.scanned_url = ""
        self.scan_sources = ("Default", "Default")
        self.wordlist = WordlistManager()  # Wordlist manager
        self.scope_path = None
        self.policy = None
        self.stop_requested = False
        self._build_ui()

    #  UI CONSTRUCTION
    def _build_ui(self):

        # -- Header --
        header = tk.Frame(self, bg=PRIMARY, pady=10)
        header.pack(fill="x")
        tk.Label(
            header,
            text="ETHICAL SCANNER",
            font=("Courier New", 20, "bold"),
            fg=ACCENT,
            bg=PRIMARY,
        ).pack()
        tk.Label(
            header,
            text="Web vulnerability scanner  |  For authorized use only",
            font=("Courier New", 10),
            fg=TEXT_DIM,
            bg=PRIMARY,
        ).pack()
        tk.Frame(self, bg=ACCENT, height=3).pack(fill="x")

        # -- URL bar --
        bar = tk.Frame(self, bg=BG, pady=8, padx=16)
        bar.pack(fill="x")
        tk.Label(
            bar, text="URL:", font=("Courier New", 12, "bold"), fg=ACCENT, bg=BG
        ).pack(side="left", padx=(0, 8))
        self.url_field = tk.Entry(
            bar,
            font=("Courier New", 13),
            bg=SURFACE_HI,
            fg=TEXT,
            insertbackground=ACCENT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        self.url_field.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 10))
        self.url_field.insert(0, "https://")
        self.scan_btn = tk.Button(
            bar,
            text="  >  FULL SCAN  ",
            font=("Courier New", 12, "bold"),
            bg=ACCENT,
            fg=INK,
            activebackground=TEXT,
            activeforeground=INK,
            disabledforeground=MUTED,
            relief="flat",
            cursor="hand2",
            command=self.start_scan,
        )
        self.scan_btn.pack(side="left")
        tk.Button(
            bar,
            text="  X  ",
            font=("Courier New", 12),
            bg=PRIMARY,
            fg=TEXT,
            relief="flat",
            cursor="hand2",
            command=self.clear_all,
        ).pack(side="left", padx=5)

        self._build_limits_bar()

        self._add_stop_button()


        # -- Body --
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # Left column: LOG
        col_left = tk.Frame(body, bg=BG, width=380)
        col_left.pack(side="left", fill="both", padx=(0, 8))
        col_left.pack_propagate(False)
        tk.Label(
            col_left,
            text="LIVE LOG",
            font=("Courier New", 10, "bold"),
            fg=TEXT_DIM,
            bg=BG,
        ).pack(anchor="w", pady=(0, 3))
        self.log_area = scrolledtext.ScrolledText(
            col_left,
            font=("Courier New", 10),
            bg=SURFACE,
            fg=ON_SURFACE,
            insertbackground=ON_SURFACE_HI,
            relief="flat",
            bd=0,
            state="disabled",
            wrap="word",
            padx=8,
            pady=6,
        )
        self.log_area.pack(fill="both", expand=True)
        self._style_scrollbar(self.log_area)
        for t, c in [
            ("info", ON_SURFACE_DIM),
            ("ok", ON_SURFACE),
            ("vuln", ON_SURFACE_HI),
            ("warn", ON_SURFACE_HI),
            ("scan", ON_SURFACE_DIM),
            ("title", ON_SURFACE_HI),
        ]:
            self.log_area.tag_config(
                t,
                foreground=c,
                font=("Courier New", 10, "bold")
                if t in ("title", "vuln")
                else ("Courier New", 10),
            )

        # Right column: TABS
        col_right = tk.Frame(body, bg=BG)
        col_right.pack(side="right", fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "TNotebook",
            background=BG,
            borderwidth=0,
            bordercolor=BORDER,
            lightcolor=BG,
            darkcolor=BG,
        )
        style.configure(
            "TNotebook.Tab",
            background=SURFACE_HI,
            foreground=TEXT_DIM,
            font=("Courier New", 10, "bold"),
            padding=[10, 5],
            borderwidth=1,
            bordercolor=BORDER,
            lightcolor=SURFACE_HI,
            darkcolor=SURFACE_HI,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", PRIMARY)],
            foreground=[("selected", ACCENT)],
        )
        style.configure(
            "Treeview",
            background=SURFACE,
            foreground=ON_SURFACE,
            fieldbackground=SURFACE,
            rowheight=30,
            font=("Courier New", 10),
            borderwidth=0,
            bordercolor=BORDER,
            lightcolor=SURFACE,
            darkcolor=SURFACE,
        )
        style.configure(
            "Treeview.Heading",
            background=PRIMARY,
            foreground=TEXT,
            font=("Courier New", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", PRIMARY)],
            foreground=[("selected", TEXT)],
        )
        style.configure(
            "TProgressbar",
            troughcolor=SURFACE_HI,
            background=ACCENT,
            bordercolor=BORDER,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )
        style.configure(
            "Vertical.TScrollbar",
            background=PRIMARY,
            troughcolor=SURFACE,
            bordercolor=BORDER,
            arrowcolor=TEXT,
        )

        self.notebook = ttk.Notebook(col_right)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Vulnerabilities
        self._tab_vulnerabilities()
        # Tab 2: Wordlists
        self._tab_wordlists()
        # Tab 3: CMS
        self._tab_cms()
        # Tab 4: Help
        self._tab_help()

        # -- Status bar --
        bottom = tk.Frame(self, bg=INK, pady=5, padx=16)
        bottom.pack(fill="x", side="bottom")
        self.status_label = tk.Label(
            bottom, text="Ready", font=("Courier New", 10), fg=TEXT, bg=INK
        )
        self.status_label.pack(side="left")
        self.progress = ttk.Progressbar(bottom, mode="indeterminate", length=140)
        self.progress.pack(side="left", padx=12)
        self.count_label = tk.Label(
            bottom, text="0 vuln", font=("Courier New", 10, "bold"), fg=TEXT_DIM, bg=INK
        )
        self.count_label.pack(side="left")
        self.wordlist_status_label = tk.Label(
            bottom,
            text=f"SQLi: {len(self.wordlist.sql_payloads)} default | XSS: {len(self.wordlist.xss_payloads)} default",
            font=("Courier New", 9),
            fg=TEXT_DIM,
            bg=INK,
        )
        self.wordlist_status_label.pack(side="left", padx=12)
        self.html_btn = tk.Button(
            bottom,
            text="HTML",
            font=("Courier New", 10),
            bg=PRIMARY,
            fg=TEXT,
            disabledforeground=MUTED,
            relief="flat",
            cursor="hand2",
            state="disabled",
            command=self.export_html,
        )
        self.html_btn.pack(side="right", padx=3)
        if PDF_AVAILABLE:
            self.pdf_btn = tk.Button(
                bottom,
                text="PDF",
                font=("Courier New", 10, "bold"),
                bg=PRIMARY,
                fg=TEXT,
                disabledforeground=MUTED,
                relief="flat",
                cursor="hand2",
                state="disabled",
                command=self.export_pdf,
            )
            self.pdf_btn.pack(side="right", padx=3)
        else:
            self.pdf_btn = None

    def _build_limits_bar(self):
        """Second row under the URL bar: request delay, timeout and scope file."""
        bar = tk.Frame(self, bg=BG, padx=16)
        bar.pack(fill="x", pady=(0, 6))
        label_font = ("Courier New", 10, "bold")
        entry_style = dict(
            font=("Courier New", 11),
            width=6,
            justify="center",
            bg=SURFACE_HI,
            fg=TEXT,
            insertbackground=ACCENT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        button_style = dict(
            font=("Courier New", 10),
            bg=PRIMARY,
            fg=TEXT,
            activebackground=BORDER,
            activeforeground=TEXT,
            relief="flat",
            cursor="hand2",
        )
        tk.Label(bar, text="DELAY (s):", font=label_font, fg=TEXT_DIM, bg=BG).pack(
            side="left", padx=(0, 6)
        )
        self.delay_entry = tk.Entry(bar, **entry_style)
        self.delay_entry.insert(0, "0")
        self.delay_entry.pack(side="left", ipady=3)
        tk.Label(bar, text="TIMEOUT (s):", font=label_font, fg=TEXT_DIM, bg=BG).pack(
            side="left", padx=(16, 6)
        )
        self.timeout_entry = tk.Entry(bar, **entry_style)
        self.timeout_entry.pack(side="left", ipady=3)
        tk.Label(bar, text="SCOPE:", font=label_font, fg=TEXT_DIM, bg=BG).pack(
            side="left", padx=(16, 6)
        )
        self.scope_label = tk.Label(
            bar,
            text="none (any target)",
            font=("Courier New", 10),
            fg=TEXT_DIM,
            bg=BG,
        )
        self.scope_label.pack(side="left")
        tk.Button(bar, text=" Browse ", command=self._pick_scope, **button_style).pack(
            side="left", padx=(10, 4)
        )
        tk.Button(bar, text=" Clear ", command=self._clear_scope, **button_style).pack(
            side="left"
        )

    def _add_stop_button(self):
        """STOP button at the right end of the limits bar (enabled during a scan)."""
        bar = self.scope_label.master
        self.stop_btn = tk.Button(
            bar,
            text=" STOP ",
            command=self.stop_scan,
            font=("Courier New", 10, "bold"),
            bg=PRIMARY,
            fg=TEXT,
            activebackground=BORDER,
            activeforeground=TEXT,
            disabledforeground=MUTED,
            relief="flat",
            cursor="hand2",
            state="disabled",
        )
        self.stop_btn.pack(side="right")

    def _engine_log(self, msg, kind="info"):
        """Engine messages go to the log, except after STOP (they would only be noise)."""
        if not self.stop_requested:
            self.log_msg(msg, kind)

    def _preflight_then_run(self, engine, url):
        """Worker thread: check that the target answers, then start the scan.
        Doing it off the main thread keeps the window responsive."""
        ok, message = check_reachable(url)
        if self.stop_requested:
            self.after(0, self._scan_stopped)
        elif not ok:
            self.after(0, lambda: self._scan_unreachable(message))
        else:
            engine.start()

    def stop_scan(self):
        if not self.scan_running or self.stop_requested:
            return
        self.stop_requested = True
        self.stop_btn.config(state="disabled")
        if self.policy is not None:
            self.policy.stop()
        self.log_msg("  Stopping: waiting for the request in progress...", "warn")

    def _reset_after_scan(self, quiet=False):
        """Common end of a scan that never reached the engine's own completion."""
        if quiet:
            policy, self.policy = self.policy, None
            if policy is not None:
                policy.deactivate()
        else:
            self._end_policy()
        self.scan_running = False
        self.progress.stop()
        self.stop_btn.config(state="disabled")
        self.scan_btn.config(state="normal", bg=ACCENT, fg=INK)

    def _scan_unreachable(self, message):
        self.log_msg(f"  {message}", "warn")
        self.log_msg(
            "  Nothing was scanned. Check the address, the port and that the service is running.",
            "info",
        )
        self._reset_after_scan(quiet=True)
        self.status_label.config(text="Target unreachable", fg=TEXT)

    def _scan_stopped(self):
        self._reset_after_scan()
        self.status_label.config(text="Scan stopped", fg=TEXT)
        self.log_msg("\n=== STOPPED ===", "title")

    def _pick_scope(self):
        path = filedialog.askopenfilename(
            title="Choose a scope file",
            initialdir=os.getcwd(),
            filetypes=[("Text files", "*.txt"), ("All files", "*")],
        )
        if path:
            self.scope_path = path
            self.scope_label.config(text=os.path.basename(path), fg=ACCENT)

    def _clear_scope(self):
        self.scope_path = None
        self.scope_label.config(text="none (any target)", fg=TEXT_DIM)

    def _log_limits(self, policy):
        if policy.scope:
            self.log_msg(f"  Scope: {policy.scope.source}", "info")
        if policy.delay:
            self.log_msg(f"  Delay: {policy.delay:g} s between requests", "info")
        if policy.timeout:
            self.log_msg(f"  Timeout: {policy.timeout:g} s per request", "info")

    def _end_policy(self):
        """Remove the request limits once the scan is over and report what they did."""
        policy, self.policy = self.policy, None
        if policy is None:
            return
        policy.deactivate()
        self.log_msg(f"  Requests sent: {policy.sent}", "info")
        if policy.blocked:
            self.log_msg(
                "  Blocked out-of-scope host(s): " + ", ".join(policy.blocked), "warn"
            )

    # -----------------------------------------
    def _tab_vulnerabilities(self):
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="Vulnerabilities")
        cols = ("Type", "Severity", "Description")
        self.table = ttk.Treeview(tab, columns=cols, show="headings")
        for col in cols:
            self.table.heading(col, text=col)
        self.table.column("Type", width=320)
        self.table.column("Severity", width=100, minwidth=100, stretch=False)
        self.table.column("Description", width=380)
        # Hierarchy on the slate panel: filled row > bold emphasis > text > dim
        self.table.tag_configure(
            "Critical",
            background=ACCENT,
            foreground=INK,
            font=("Courier New", 10, "bold"),
        )
        self.table.tag_configure(
            "High", foreground=ON_SURFACE_HI, font=("Courier New", 10, "bold")
        )
        self.table.tag_configure("Medium", foreground=ON_SURFACE)
        self.table.tag_configure("Low", foreground=ON_SURFACE_DIM)
        sb = ttk.Scrollbar(tab, orient="vertical", command=self.table.yview)
        hsb = ttk.Scrollbar(tab, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=sb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        sb.pack(side="right", fill="y")
        self.table.pack(side="left", fill="both", expand=True)

    # -----------------------------------------
    def _tab_wordlists(self):
        """
        Full wordlist management tab.
        Lets you load .txt files of SQLi and XSS payloads.
        """
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="Wordlists")

        # -- Title --
        title_frame = tk.Frame(tab, bg=BG, pady=10, padx=14)
        title_frame.pack(fill="x")
        tk.Label(
            title_frame,
            text="PAYLOAD WORDLIST MANAGEMENT",
            font=("Courier New", 13, "bold"),
            fg=ACCENT,
            bg=BG,
        ).pack(anchor="w")
        tk.Label(
            title_frame,
            text="Load your own .txt payload files for SQLi and XSS (one entry per line, # = comment)",
            font=("Courier New", 10),
            fg=TEXT_DIM,
            bg=BG,
        ).pack(anchor="w", pady=(2, 0))

        tk.Label(
            title_frame,
            text="Sample wordlists are in the 'wordlists/' folder next to this script",
            font=("Courier New", 10),
            fg=TEXT,
            bg=BG,
        ).pack(anchor="w", pady=(2, 0))

        sep = tk.Frame(tab, bg=BORDER, height=1)
        sep.pack(fill="x", padx=14, pady=4)

        # Scrollable container for the two sections
        content = tk.Frame(tab, bg=BG)
        content.pack(fill="both", expand=True, padx=14, pady=4)

        # -- SQLi section
        self._wordlist_section(
            parent=content,
            title="SQLi WORDLIST (SQL Injection)",
            color=ACCENT,
            payload_type="sql",
        )

        tk.Frame(content, bg=BORDER, height=1).pack(fill="x", pady=8)

        # -- XSS section
        self._wordlist_section(
            parent=content,
            title="XSS WORDLIST (Cross-Site Scripting)",
            color=TEXT,
            payload_type="xss",
        )

    def _wordlist_section(self, parent, title, color, payload_type):
        """
        Builds a wordlist section (SQLi or XSS) with:
        - File picker
        - Load / reset buttons
        - Payload counter
        - Preview of loaded payloads
        """
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="both", expand=True)

        # Section title
        tk.Label(
            frame, text=title, font=("Courier New", 12, "bold"), fg=color, bg=BG
        ).pack(anchor="w", pady=(4, 6))

        # Row: file field + buttons
        file_row = tk.Frame(frame, bg=BG)
        file_row.pack(fill="x", pady=(0, 6))

        # File path field
        field = tk.Entry(
            file_row,
            font=("Courier New", 11),
            bg=SURFACE_HI,
            fg=TEXT_DIM,
            insertbackground=ACCENT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=color,
            width=52,
        )
        field.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 6))
        field.insert(0, "No file loaded - using default payloads")

        # Browse button
        def browse():
            file_path = filedialog.askopenfilename(
                title=f"Choose the {payload_type.upper()} wordlist",
                initialdir=SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else os.getcwd(),
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            )
            if file_path:
                field.delete(0, "end")
                field.insert(0, file_path)
                field.config(fg=TEXT)

        tk.Button(
            file_row,
            text="Browse",
            font=("Courier New", 10),
            bg=PRIMARY,
            fg=TEXT,
            relief="flat",
            cursor="hand2",
            command=browse,
        ).pack(side="left", padx=(0, 4))

        # Counter label (dynamic)
        count_label = tk.Label(
            file_row,
            text=f"{len(self.wordlist.sql_payloads if payload_type == 'sql' else self.wordlist.xss_payloads)} payloads",
            font=("Courier New", 10, "bold"),
            fg=color,
            bg=BG,
            width=12,
        )
        count_label.pack(side="left", padx=(0, 4))

        # Payload preview area
        preview_frame = tk.Frame(frame, bg=SURFACE, bd=0)
        preview_frame.pack(fill="both", expand=True, pady=(0, 4))

        tk.Label(
            preview_frame,
            text="Active payload preview:",
            font=("Courier New", 9, "bold"),
            fg=ON_SURFACE_DIM,
            bg=SURFACE,
        ).pack(anchor="w", padx=8, pady=(4, 0))

        preview_area = scrolledtext.ScrolledText(
            preview_frame,
            font=("Courier New", 10),
            bg=SURFACE,
            fg=ON_SURFACE_HI if payload_type == "sql" else ON_SURFACE,
            relief="flat",
            bd=0,
            height=6,
            state="normal",
            padx=8,
            pady=4,
            wrap="none",
        )
        preview_area.pack(fill="both", expand=True)
        self._style_scrollbar(preview_area)

        def update_preview(payloads):
            """Refreshes the preview area."""
            preview_area.config(state="normal")
            preview_area.delete(1.0, "end")
            for i, p in enumerate(payloads[:50], 1):
                preview_area.insert("end", f"  {i:>3}. {p}\n")
            if len(payloads) > 50:
                preview_area.insert(
                    "end",
                    f"\n  ... and {len(payloads) - 50} more payloads\n",
                )
            preview_area.config(state="disabled")

        # Show default payloads on startup
        update_preview(
            self.wordlist.sql_payloads
            if payload_type == "sql"
            else self.wordlist.xss_payloads
        )

        # Load / reset buttons
        btn_row = tk.Frame(frame, bg=BG)
        btn_row.pack(fill="x", pady=(2, 0))

        def load():
            """Loads the wordlist from the selected file."""
            file_path = field.get().strip()
            if not file_path or "No file" in file_path:
                messagebox.showwarning("No file", "Select a .txt file first")
                return

            if payload_type == "sql":
                ok, error, nb = self.wordlist.apply_sql(file_path)
            else:
                ok, error, nb = self.wordlist.apply_xss(file_path)

            if not ok:
                messagebox.showerror("Error", f"Could not load:\n{error}")
                return

            payloads = (
                self.wordlist.sql_payloads
                if payload_type == "sql"
                else self.wordlist.xss_payloads
            )
            update_preview(payloads)
            count_label.config(text=f"{nb} payloads")
            self._update_wordlist_status()
            self.log_msg(
                f"Wordlist {payload_type.upper()} loaded: {nb} payloads from {os.path.basename(file_path)}",
                "ok",
            )
            messagebox.showinfo(
                "Loaded",
                f"{nb} {payload_type.upper()} payloads loaded\n\nFile: {os.path.basename(file_path)}",
            )

        def reset():
            """Restores the default payloads."""
            if payload_type == "sql":
                self.wordlist.reset_sql()
            else:
                self.wordlist.reset_xss()
            payloads = (
                self.wordlist.sql_payloads
                if payload_type == "sql"
                else self.wordlist.xss_payloads
            )
            field.delete(0, "end")
            field.insert(0, "No file loaded - using default payloads")
            field.config(fg=TEXT_DIM)
            update_preview(payloads)
            count_label.config(text=f"{len(payloads)} payloads")
            self._update_wordlist_status()
            self.log_msg(f"Wordlist {payload_type.upper()} reset to defaults", "info")

        tk.Button(
            btn_row,
            text="LOAD THIS WORDLIST",
            font=("Courier New", 11, "bold"),
            bg=ACCENT,
            fg=INK,
            relief="flat",
            cursor="hand2",
            command=load,
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_row,
            text="Reset to default",
            font=("Courier New", 10),
            bg=SURFACE_HI,
            fg=TEXT_DIM,
            relief="flat",
            cursor="hand2",
            command=reset,
        ).pack(side="left")

        # Format info label
        tk.Label(
            btn_row,
            text="  .txt format: one entry per line, # for comments",
            font=("Courier New", 9),
            fg=TEXT_DIM,
            bg=BG,
        ).pack(side="left", padx=12)

    # -----------------------------------------
    def _tab_cms(self):
        tab_cms = tk.Frame(self.notebook, bg=BG, padx=14, pady=14)
        self.notebook.add(tab_cms, text="CMS Detection")
        tk.Label(
            tab_cms,
            text="AUTOMATIC CMS DETECTION",
            font=("Courier New", 13, "bold"),
            fg=ACCENT,
            bg=BG,
        ).pack(anchor="w")
        tk.Label(
            tab_cms,
            text="WordPress, Joomla, Drupal, Magento, Laravel...",
            font=("Courier New", 10),
            fg=TEXT_DIM,
            bg=BG,
        ).pack(anchor="w", pady=(2, 10))
        self.cms_frame = tk.Frame(tab_cms, bg=BG)
        self.cms_frame.pack(fill="both", expand=True)
        self.cms_empty_label = tk.Label(
            self.cms_frame,
            text="Run a scan to detect the target site's CMS.",
            font=("Courier New", 12),
            fg=TEXT_DIM,
            bg=BG,
        )
        self.cms_empty_label.pack(pady=40)

    # -----------------------------------------
    def _tab_help(self):
        tab_help = tk.Frame(self.notebook, bg=BG, padx=14, pady=14)
        self.notebook.add(tab_help, text="Help")
        help_text = """ETHICALSCANNER FEATURES
===========================================

[x] Basic tests (HTTPS, headers, sensitive paths)
[x] HTML form scanning (SQLi, XSS)
[x] Custom payload wordlists
[x] Automatic CMS detection
[x] HTML and PDF reports

===========================================
USING WORDLISTS

1. Click the "Wordlists" tab
2. Click "Browse" (it opens the bundled "wordlists/" folder):
   -> sqli_samples.txt      (SQL injection)
   -> xss_samples.txt       (cross-site scripting)
   -> sqli_destructive.txt  (modifies data! lab use only)
3. Or pick your own .txt file
4. Click "LOAD THIS WORDLIST"
5. Run the scan!

WORDLIST FILE FORMAT:
  # This is a comment (ignored)
  ' OR '1'='1
  <script>alert('XSS')</script>
  (one entry per line)

POPULAR WORDLIST SOURCES:
  - SecLists (GitHub danielmiessler/SecLists)
  - PayloadsAllTheThings (GitHub swisskyrepo)
  - OWASP Testing Guide payloads

===========================================
FOR AUTHORIZED, ETHICAL USE ONLY
    Only test sites you own or for which
    you have explicit written authorization.
"""
        z = scrolledtext.ScrolledText(
            tab_help,
            font=("Courier New", 11),
            bg=SURFACE,
            fg=ON_SURFACE,
            relief="flat",
            bd=0,
            padx=10,
            pady=10,
        )
        z.insert("end", help_text)
        z.config(state="disabled")
        z.pack(fill="both", expand=True)
        self._style_scrollbar(z)

    #  UTILITY METHODS
    @staticmethod
    def _style_scrollbar(widget):
        """ScrolledText ships a classic tk scrollbar: recolor it to match the theme."""
        widget.vbar.config(
            bg=PRIMARY,
            troughcolor=SURFACE,
            activebackground=ACCENT,
            highlightthickness=0,
            bd=0,
            relief="flat",
        )
        widget.config(
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=BORDER
        )

    def _update_wordlist_status(self):
        """Updates the wordlist status label in the bottom bar."""
        sql_info = (
            f"{len(self.wordlist.sql_payloads)} custom"
            if self.wordlist.sql_file
            else f"{len(self.wordlist.sql_payloads)} default"
        )
        xss_info = (
            f"{len(self.wordlist.xss_payloads)} custom"
            if self.wordlist.xss_file
            else f"{len(self.wordlist.xss_payloads)} default"
        )
        self.wordlist_status_label.config(
            text=f"SQLi: {sql_info} | XSS: {xss_info}",
            fg=ACCENT
            if (self.wordlist.sql_file or self.wordlist.xss_file)
            else TEXT_DIM,
        )

    def log_msg(self, msg, msg_type="info"):
        def _():
            self.log_area.config(state="normal")
            self.log_area.insert("end", f"{msg}\n", msg_type)
            self.log_area.see("end")
            self.log_area.config(state="disabled")

        self.after(0, _)

    def add_vuln(self, vuln):
        def _():
            desc = (
                vuln["description"][:55] + "..."
                if len(vuln["description"]) > 55
                else vuln["description"]
            )
            self.table.insert(
                "",
                "end",
                values=(vuln["type"], vuln["severity"], desc),
                tags=(vuln["severity"],),
            )
            nb = len(self.table.get_children())
            self.count_label.config(text=f"{nb} vuln", fg=ACCENT if nb > 0 else TEXT)

        self.after(0, _)

    def update_cms_ui(self, detected_cms):
        def _():
            for w in self.cms_frame.winfo_children():
                w.destroy()
            if not detected_cms:
                tk.Label(
                    self.cms_frame,
                    text="No known CMS detected",
                    font=("Courier New", 12),
                    fg=TEXT,
                    bg=BG,
                ).pack(pady=30)
                return
            self.notebook.tab(2, text=f"CMS ({len(detected_cms)})")
            for cms in detected_cms:
                card = tk.Frame(self.cms_frame, bg=SURFACE_HI, pady=8, padx=12)
                card.pack(fill="x", pady=3)
                l1 = tk.Frame(card, bg=SURFACE_HI)
                l1.pack(fill="x")
                tk.Label(
                    l1,
                    text=f"{cms['icon']} {cms['name']}",
                    font=("Courier New", 14, "bold"),
                    fg=ACCENT,
                    bg=SURFACE_HI,
                ).pack(side="left")
                tk.Label(
                    l1,
                    text=f"  confidence {cms['confidence']}%",
                    font=("Courier New", 10),
                    fg=TEXT,
                    bg=SURFACE_HI,
                ).pack(side="left")
                for p in cms["evidence"]:
                    tk.Label(
                        card,
                        text=f"  -> {p}",
                        font=("Courier New", 10),
                        fg=TEXT,
                        bg=SURFACE_HI,
                    ).pack(anchor="w")
                for r in cms["known_vulns"]:
                    tk.Label(
                        card,
                        text=f"  ! {r}",
                        font=("Courier New", 10),
                        fg=ACCENT,
                        bg=SURFACE_HI,
                        wraplength=600,
                        justify="left",
                    ).pack(anchor="w")

        self.after(0, _)

    #  SCAN
    def start_scan(self):
        url = self.url_field.get().strip()
        if not url or url == "https://":
            messagebox.showwarning("Missing URL", "Enter a valid URL!")
            return
        if self.scan_running:
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        policy, error = build_request_policy(
            url, self.scope_path, self.delay_entry.get(), self.timeout_entry.get()
        )
        if error:
            messagebox.showwarning("Scan limits", error)
            return
        self.clear_all()
        self.scanned_url = url
        self.scan_running = True
        self.scan_btn.config(state="disabled", bg=SURFACE_HI, fg=MUTED)
        self.stop_requested = False
        self.stop_btn.config(state="normal")
        self.progress.start(10)
        self.status_label.config(text="Scan in progress...", fg=ACCENT)

        sql_src = (
            f"file ({os.path.basename(self.wordlist.sql_file)})"
            if self.wordlist.sql_file
            else "default"
        )
        xss_src = (
            f"file ({os.path.basename(self.wordlist.xss_file)})"
            if self.wordlist.xss_file
            else "default"
        )
        # Remember what was used for THIS scan, even if wordlists change before export
        self.scan_sources = self._wordlist_sources()
        self.log_msg(f"=== SCAN: {url} ===", "title")
        self.log_msg(
            f"  SQLi: {len(self.wordlist.sql_payloads)} payloads [{sql_src}]", "info"
        )
        self.log_msg(
            f"  XSS : {len(self.wordlist.xss_payloads)} payloads [{xss_src}]", "info"
        )

        # Pass the custom payloads to the engine
        engine = ScanEngine(
            url=url,
            sql_payloads=list(self.wordlist.sql_payloads),
            xss_payloads=list(self.wordlist.xss_payloads),
            log_callback=self._engine_log,
            vuln_callback=self.add_vuln,
            cms_callback=self.update_cms_ui,
            done_callback=self.scan_done,
        )
        self._log_limits(policy)
        policy.activate()
        self.policy = policy
        try:
            threading.Thread(
                target=self._preflight_then_run, args=(engine, url), daemon=True
            ).start()
        except Exception:
            self._reset_after_scan(quiet=True)
            raise

    def scan_done(self, results, detected_cms):
        def _():
            self._end_policy()
            self.scan_results = results
            self.scanned_cms = detected_cms
            self.scan_running = False
            self.progress.stop()
            self.stop_btn.config(state="disabled")
            nb = len(results)
            self.status_label.config(
                text=f"{'Stopped' if self.stop_requested else 'Done'} - {nb} vuln | {len(detected_cms)} CMS",
                fg=ACCENT if nb > 0 else TEXT,
            )
            self.scan_btn.config(state="normal", bg=ACCENT, fg=INK)
            self.html_btn.config(state="normal")
            if self.pdf_btn:
                self.pdf_btn.config(state="normal")
            self.log_msg(
                f"\n=== {'STOPPED' if self.stop_requested else 'DONE'}: {nb} vulnerabilit{'y' if nb == 1 else 'ies'} | {len(detected_cms)} CMS ===",
                "title",
            )

        self.after(0, _)

    def clear_all(self):
        self.log_area.config(state="normal")
        self.log_area.delete(1.0, "end")
        self.log_area.config(state="disabled")
        for item in self.table.get_children():
            self.table.delete(item)
        for w in self.cms_frame.winfo_children():
            w.destroy()
        self.cms_empty_label = tk.Label(
            self.cms_frame,
            text="Run a scan to detect the target site's CMS.",
            font=("Courier New", 12),
            fg=TEXT_DIM,
            bg=BG,
        )
        self.cms_empty_label.pack(pady=40)
        self.notebook.tab(2, text="CMS Detection")
        self.scan_results = []
        self.scanned_cms = []
        self.count_label.config(text="0 vuln", fg=TEXT_DIM)
        self.status_label.config(text="Ready", fg=TEXT)
        self.html_btn.config(state="disabled")
        if self.pdf_btn:
            self.pdf_btn.config(state="disabled")

    #  EXPORT
    def _report_filename(self, ext):
        """Safe file name: a host:port netloc would contain ':' (invalid on Windows)."""
        host = (
            re.sub(r"[^A-Za-z0-9_-]+", "_", urlparse(self.scanned_url).netloc)
            or "target"
        )
        return f"report_{host}_{datetime.now().strftime('%Y%m%d_%H%M')}.{ext}"

    def _wordlist_sources(self):
        """Human-readable description of the wordlists currently loaded."""
        wl = self.wordlist
        sql = (
            f"{os.path.basename(wl.sql_file)} ({len(wl.sql_payloads)} payloads)"
            if wl.sql_file
            else f"Default ({len(wl.sql_payloads)} payloads)"
        )
        xss = (
            f"{os.path.basename(wl.xss_file)} ({len(wl.xss_payloads)} payloads)"
            if wl.xss_file
            else f"Default ({len(wl.xss_payloads)} payloads)"
        )
        return sql, xss

    def export_html(self):
        name = self._report_filename("html")
        sql_src, xss_src = self.scan_sources
        domain = urlparse(self.scanned_url).netloc
        date = datetime.now().strftime("%Y-%m-%d %H:%M")
        stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r in self.scan_results:
            if r["severity"] in stats:
                stats[r["severity"]] += 1

        # (background, text, border) per severity
        sev_style = {
            "Critical": (ACCENT, INK, ACCENT),
            "High": (PRIMARY, TEXT, ACCENT),
            "Medium": (TEXT_DIM, INK, TEXT_DIM),
            "Low": (SURFACE_HI, TEXT_DIM, TEXT_DIM),
        }

        def badge(sev):
            bg, fg, bd = sev_style.get(sev, (SURFACE_HI, TEXT_DIM, TEXT_DIM))
            return (
                f'<span class="badge" style="background:{bg};color:{fg};'
                f'border-color:{bd}">{escape(sev)}</span>'
            )

        # Everything coming from the scan is escaped: payloads are raw HTML/JS
        rows = (
            "".join(
                f"<tr><td>{escape(r['type'])}</td><td>{badge(r['severity'])}</td>"
                f'<td>{escape(r["description"])}</td><td class="detail">{escape(r["detail"])}</td></tr>'
                for r in self.scan_results
            )
            or '<tr><td colspan="4" class="empty">No vulnerabilities found</td></tr>'
        )

        tiles = "".join(
            f'<div class="stat" style="background:{sev_style[sev][0]};color:{sev_style[sev][1]};'
            f'border-color:{sev_style[sev][2]}"><div class="n">{stats[sev]}</div>'
            f'<div class="l">{sev.upper()}</div></div>'
            for sev in stats
        )

        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report - {escape(domain)}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:{BG};color:{TEXT};line-height:1.5}}
header{{background:{PRIMARY};border-bottom:4px solid {ACCENT};padding:28px 30px}}
h1{{color:{ACCENT};font-size:1.7rem}}
header p{{color:{TEXT_DIM};font-size:.85rem;margin-top:4px}}
main{{padding:30px}}
h2{{color:{ACCENT};font-size:1.05rem;margin:26px 0 10px;border-bottom:1px solid {BORDER};padding-bottom:6px}}
p{{color:{TEXT_DIM};font-size:.9rem;margin-bottom:4px}}
p strong{{color:{TEXT}}}
.wl{{background:{SURFACE_HI};border:1px solid {BORDER};border-left:4px solid {ACCENT};padding:10px 14px;margin:14px 0;font-size:.82rem;color:{TEXT_DIM}}}
.wl span{{color:{ACCENT}}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}}
.stat{{border:1px solid;padding:14px;text-align:center;font-weight:bold}}
.stat .n{{font-size:2rem}}.stat .l{{font-size:.75rem;letter-spacing:.08em}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:{SURFACE};border:1px solid {BORDER}}}
th{{background:{PRIMARY};padding:10px 12px;text-align:left;color:{TEXT};font-size:.82rem}}
td{{padding:9px 12px;border-bottom:1px solid {BORDER};font-size:.82rem;vertical-align:top;color:{ON_SURFACE}}}
td.detail{{color:{ON_SURFACE_DIM}}}
td.empty{{text-align:center;color:{ON_SURFACE_HI}}}
.badge{{display:inline-block;border:1px solid;padding:1px 8px;font-size:.78rem}}
footer{{text-align:center;color:{TEXT_DIM};padding:30px;font-size:.8rem}}
@media(max-width:640px){{.stats{{grid-template-columns:repeat(2,1fr)}}main{{padding:20px 16px}}header{{padding:22px 16px}}}}
</style></head>
<body>
<header><h1>Security Report</h1><p>EthicalScanner</p></header>
<main>
<p>Target: <strong>{escape(self.scanned_url)}</strong></p>
<p>Date: {date}</p>
<div class="wl">Wordlists used:<br>
  <span>SQLi:</span> {escape(sql_src)}<br>
  <span>XSS:</span> {escape(xss_src)}
</div>
<div class="stats">{tiles}</div>
<h2>Vulnerabilities Found</h2>
<div class="table-wrap"><table><thead><tr><th>TYPE</th><th>SEVERITY</th><th>DESCRIPTION</th><th>DETAILS</th></tr></thead>
<tbody>{rows}</tbody></table></div>
</main>
<footer>Confidential report - EthicalScanner</footer>
</body></html>"""
        with open(name, "w", encoding="utf-8") as f:
            f.write(html)
        webbrowser.open(Path(name).resolve().as_uri())
        self.log_msg(f"HTML report saved: {name}", "ok")

    def export_pdf(self):
        if not PDF_AVAILABLE:
            messagebox.showwarning("ReportLab missing", "pip install reportlab")
            return
        name = self._report_filename("pdf")
        sql_src, xss_src = self.scan_sources
        try:
            gen = PDFReportGenerator(
                self.scanned_url,
                self.scan_results,
                name,
                sql_source=sql_src,
                xss_source=xss_src,
            )
            gen.generate()
            self.log_msg(f"PDF report saved: {name}", "ok")
            messagebox.showinfo("PDF generated", f"File: {name}")
            if sys.platform == "win32":
                os.startfile(name)
            else:
                webbrowser.open(Path(name).resolve().as_uri())
        except Exception as e:
            messagebox.showerror("PDF error", str(e))


#  ENTRY POINT
if __name__ == "__main__":
    if not GUI_AVAILABLE:
        sys.exit("Tkinter is not available. Install it (e.g. sudo pacman -S tk) "
                 "or use the command-line version: python ethical_scanner_cli.py --help")
    app = ScannerApp()
    app.mainloop()
