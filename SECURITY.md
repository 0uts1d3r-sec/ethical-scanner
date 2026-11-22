# Security Policy

## Reporting a vulnerability in EthicalScanner

If you find a security problem **in this tool itself** (for example unsafe handling of
untrusted responses, report injection, unsafe file writes or a way to bypass the
safeguards for destructive payloads), please report it privately:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** and describe the issue, the affected version and,
   if possible, steps to reproduce it.

Please do not open a public issue for security problems. I will acknowledge reports on a
best-effort basis and credit reporters who want it once a fix is released.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: the code in this repository (`ethical_scanner.py`, `ethical_scanner_cli.py`).

Out of scope:

- Findings the scanner reports about third-party websites.
- Misuse of the tool against systems you are not authorized to test.

## Responsible use

EthicalScanner is intended for **authorized security testing only**: your own systems,
lab environments, or targets covered by a bug bounty program scope or written permission.
The wordlist `wordlists/sqli_destructive.txt` can modify or delete data; use it only on a
disposable lab database you own. Unauthorized scanning is illegal in most jurisdictions.
