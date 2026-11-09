#!/usr/bin/env python3
"""secret-finder: find passwords and keys committed by mistake in a change.

Scans only the *added* lines of a unified diff and reports file, new-file line
number and a short reason for each finding. Exits 1 when anything is found, so
it can be used as a pre-commit hook or CI step.

The detection approach borrows from mature scanners:
  * provider-specific key formats (regexes adapted from gitleaks' default config,
    the same idea as GitHub secret scanning's "provider patterns"),
  * keyword assignments like `password = "..."` (gitleaks generic-api-key,
    detect-secrets KeywordDetector),
  * high-entropy quoted strings (detect-secrets' Base64/Hex entropy plugins,
    with their default limits of 4.5 and 3.0 bits per char),
  * inline allowlist comments and placeholder stopwords to cut false positives.

Standard library only. Usage: see README.md or `secret_finder.py --help`.
"""
from __future__ import annotations

import argparse
import math
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Iterator

# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

# Known formats: high confidence, so no entropy or stopword filtering.
# (rule id, regex, reason)
KNOWN_FORMATS: list[tuple[str, re.Pattern[str], str]] = [
    ("private-key", re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"),
     "private key header"),
    ("aws-access-key-id", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
     "AWS access key ID"),
    ("github-token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36})\b"),
     "GitHub token"),
    ("github-fine-grained-pat", re.compile(r"\b(github_pat_\w{82})\b"),
     "GitHub fine-grained personal access token"),
    ("slack-token", re.compile(r"\b(xox[baprse]-[0-9]{10,13}-[0-9a-zA-Z-]{10,})"),
     "Slack token"),
    ("stripe-secret-key", re.compile(r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b"),
     "Stripe secret/restricted key"),
    ("gcp-api-key", re.compile(r"\b(AIza[\w-]{35})(?![\w-])"),
     "Google API key"),
    ("jwt", re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
     "JSON Web Token"),
    ("url-credentials", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'\"]+:([^/\s@'\"]{3,})@[^\s'\"]+"),
     "credentials embedded in a URL"),
]

# `password = "hunter2"`, `API_KEY: abc...`, `"secret": "..."`, `token => '...'`
KEYWORD_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[\w.-]*(?:passw(?:or)?d|pwd|secret|token|api[_.-]?key|apikey|
                     access[_.-]?key|private[_.-]?key|auth[_.-]?key|credentials?)[\w.-]*)
    ['"]?\s*(?::=|=>|==?|:)\s*
    (?P<quote>['"`]?)(?P<value>[^\s'"`,;]{6,})(?P=quote)
    """
)

QUOTED_STRING = re.compile(r"""(['"`])([^'"`\s]{20,})\1""")
BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/=_-]+$")
HEX_CHARS = re.compile(r"^[0-9a-fA-F]+$")
BASE64_ENTROPY_LIMIT = 4.5  # detect-secrets default
HEX_ENTROPY_LIMIT = 3.0     # detect-secrets default

# Values that are clearly not secrets: placeholders, env/template references, code.
PLACEHOLDER_WORDS = ("example", "sample", "dummy", "placeholder", "changeme", "change_me",
                     "your_", "your-", "<", "xxxx", "****", "redacted", "todo", "none", "null")
NOT_A_LITERAL = re.compile(
    r"""(?x)
    ^\$\{?\w+\}?$          # $VAR / ${VAR}
    | \$\{ | ^- | \}$       # ${VAR:-default} and other shell/compose interpolation
    | ^\{\{.*\}\}$         # {{ template }}
    | ^%\(?\w+\)?s?%?$     # %(name)s / %VAR%
    | [()]                  # function call: os.getenv(...), getpass()
    | ^[./~]                # file path: /etc/ssl/key.pem, ./certs
    | ^[\w]+\.[\w.\[\]]+$  # attribute access: settings.SECRET_KEY, config.token
    | ^(true|false|null|none|nil|undefined)$
    """,
    re.IGNORECASE,
)

CONFIG_FILE = re.compile(r"(?:^|/)\.env(?:\.[\w.-]+)?$|\.(?:env|ini|cfg|conf|properties|ya?ml|toml)$")
IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")  # camelCase names have high entropy too
ALLOW_COMMENT = re.compile(r"pragma:\s*allowlist\s+secret|secret-finder:\s*ignore", re.I)
SKIPPED_PATHS = re.compile(
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum)$"
    r"|\.(?:png|jpe?g|gif|ico|svg|pdf|woff2?|ttf|min\.js)$"
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    reason: str
    match: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.reason} ({redact(self.match)})"


def redact(value: str) -> str:
    """Show just enough of the match to locate it, without re-leaking it."""
    return value[:4] + "…" if len(value) > 4 else "…"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def looks_like_identifier(value: str) -> bool:
    """`calendarTokenRepository` is code; `q8VzLp3RwX9kTm2Y` is not."""
    return bool(IDENTIFIER.match(value)) and sum(c.isdigit() for c in value) < 3


def looks_like_placeholder(value: str) -> bool:
    lower = value.lower()
    if any(w in lower for w in PLACEHOLDER_WORDS):
        return True
    if len(set(value)) <= 2:  # "aaaaaaaa", "********", "00000000"
        return True
    return bool(NOT_A_LITERAL.search(value))


# --------------------------------------------------------------------------- #
# Line scanning
# --------------------------------------------------------------------------- #

def scan_line(path: str, lineno: int, text: str) -> Finding | None:
    """Return the most specific finding for one added line, or None."""
    if ALLOW_COMMENT.search(text):
        return None

    for rule, pattern, reason in KNOWN_FORMATS:
        m = pattern.search(text)
        if m:
            return Finding(path, lineno, rule, reason, m.group(m.lastindex or 0))

    m = KEYWORD_ASSIGNMENT.search(text)
    if m and not looks_like_placeholder(m.group("value")):
        # In source code an unquoted value is usually an identifier
        # (`token = make_token`), so require it to look random. In config files
        # (.env, YAML, INI...) unquoted values are literals, like quoted ones.
        value = m.group("value")
        is_literal = (m.group("quote") or CONFIG_FILE.search(path)
                      or (shannon_entropy(value) >= 3.5 and not looks_like_identifier(value)))
        if is_literal:
            return Finding(path, lineno, "keyword-assignment",
                           f"hard-coded value assigned to '{m.group('key').strip('.-')}'", value)

    for m in QUOTED_STRING.finditer(text):
        value = m.group(2)
        if looks_like_placeholder(value):
            continue
        if HEX_CHARS.match(value) and len(value) >= 32:
            if shannon_entropy(value) > HEX_ENTROPY_LIMIT:
                return Finding(path, lineno, "high-entropy-hex",
                               f"high-entropy hex string ({shannon_entropy(value):.1f} bits/char)", value)
        elif BASE64_CHARS.match(value) and shannon_entropy(value) > BASE64_ENTROPY_LIMIT:
            return Finding(path, lineno, "high-entropy-string",
                           f"high-entropy string ({shannon_entropy(value):.1f} bits/char)", value)
    return None


# --------------------------------------------------------------------------- #
# Diff parsing
# --------------------------------------------------------------------------- #

HUNK_HEADER = re.compile(r"^@@+ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(diff: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    """Yield (path, new_line_number, text) for every added line in a unified diff."""
    path: str | None = None
    lineno = 0
    in_hunk = False
    for raw in diff:
        line = raw.rstrip("\n").rstrip("\r")
        if line.startswith("diff --git"):
            path, in_hunk = None, False
        elif line.startswith("+++ ") and not in_hunk:
            target = line[4:].split("\t")[0].strip().strip('"')
            path = None if target == "/dev/null" else re.sub(r"^b/", "", target)
        elif m := HUNK_HEADER.match(line):
            lineno, in_hunk = int(m.group(1)), True
        elif not in_hunk or path is None:
            continue
        elif line.startswith("+"):
            yield path, lineno, line[1:]
            lineno += 1
        elif line.startswith(" ") or line == "":
            lineno += 1
        # "-" lines and "\ No newline at end of file" do not advance the new file.


def scan_diff(diff: Iterable[str]) -> list[Finding]:
    findings = []
    for path, lineno, text in added_lines(diff):
        if SKIPPED_PATHS.search(path):
            continue
        finding = scan_line(path, lineno, text)
        if finding:
            findings.append(finding)
    return findings


# --------------------------------------------------------------------------- #
# Inputs
# --------------------------------------------------------------------------- #

GIT = ["git", "-c", "core.quotepath=off", "-c", "diff.noprefix=false"]
DIFF_FLAGS = ["--no-color", "--no-ext-diff", "--unified=0"]
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's well-known empty tree


def git(*args: str) -> str:
    result = subprocess.run([*GIT, *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    if result.returncode != 0:
        print(f"secret-finder: git {' '.join(args)} failed: {(result.stderr.strip().splitlines() or [''])[0]}",
              file=sys.stderr)
        sys.exit(2)  # 1 is reserved for "secrets found"
    return result.stdout


def commit_diff(rev: str) -> str:
    # First-parent diff so merge commits are scanned too (as "what this merge added").
    return git("show", "--format=", "--diff-merges=first-parent", *DIFF_FLAGS, rev)


def working_tree_diff() -> str:
    """Staged + unstaged changes against HEAD, plus untracked files as all-new."""
    git("rev-parse", "--is-inside-work-tree")  # clear error outside a repo
    has_head = subprocess.run([*GIT, "rev-parse", "--verify", "-q", "HEAD"],
                              capture_output=True).returncode == 0
    diff = git("diff", "HEAD" if has_head else EMPTY_TREE, *DIFF_FLAGS)
    for path in git("ls-files", "--others", "--exclude-standard", "-z").split("\0"):
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
        diff += f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n"
        diff += "".join(f"+{l}\n" for l in lines)
    return diff


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secret-finder",
        description="Find secrets in the added lines of a change. "
                    "With no arguments, scans uncommitted changes in the current git repo.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--diff", metavar="FILE", help="unified diff file to scan ('-' for stdin)")
    source.add_argument("--commit", metavar="REV", help="commit hash (or any git revision) to scan")
    args = parser.parse_args(argv)

    if args.diff == "-":
        text = sys.stdin.read()
    elif args.diff:
        with open(args.diff, encoding="utf-8", errors="replace") as f:
            text = f.read()
    elif args.commit:
        text = commit_diff(args.commit)
    else:
        text = working_tree_diff()

    findings = scan_diff(text.splitlines())
    for finding in findings:
        print(finding.format())
    if findings:
        print(f"\n{len(findings)} potential secret(s) found.", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
