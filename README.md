# secret-finder

A small CLI that finds passwords and keys committed by mistake in a change. It
scans only the **added** lines of a diff and prints `file:line: [rule] reason`
for each finding. The matched value is redacted in the output. Exit code is `1`
when something is found, `0` when the change is clean and `2` on usage errors,
so it works as a pre-commit hook or CI step.

Single file, Python 3.10+, standard library only.

## Run it

```bash
# Uncommitted changes in the current repo: staged + unstaged + untracked files
python3 secret_finder.py

# A commit (hash, tag, HEAD~1, ...)
python3 secret_finder.py --commit 3f2a9c1

# A diff file, or a diff on stdin
python3 secret_finder.py --diff change.patch
git diff main...feature | python3 secret_finder.py --diff -
```

Example output:

```
config/settings.py:12: [aws-access-key-id] AWS access key ID (AKIA…)
.env:3: [keyword-assignment] hard-coded value assigned to 'SMTP_PASSWORD' (hunt…)
```

To silence a known false positive, add `# pragma: allowlist secret` (the
detect-secrets convention) or `secret-finder: ignore` to the line.

Use it as a pre-commit hook:

```bash
printf '#!/bin/sh\ngit diff --cached | python3 /path/to/secret_finder.py --diff -\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Tests:

```bash
python3 -m unittest -v
```

## How it works

I copied the design from mature scanners instead of inventing one:

| Layer | What | Borrowed from |
|---|---|---|
| Known formats | AWS key IDs, GitHub/Slack/Stripe/Google tokens, JWTs, private key headers, `scheme://user:pass@host` | gitleaks' default rules; GitHub secret scanning's "provider patterns" |
| Keyword assignment | `password = "…"`, `API_KEY: …`, `"secret": "…"` | gitleaks `generic-api-key`, detect-secrets `KeywordDetector` |
| High entropy | Quoted strings of 20+ chars above 4.5 bits/char (base64) or 3.0 bits/char (hex, 32+ chars) | detect-secrets `Base64/HexHighEntropyString` default limits |
| Filters | Placeholders (`changeme`, `your-…`, `<…>`), env/template refs (`${X}`, `os.getenv(…)`), lockfiles and binaries, inline allowlist comment | gitleaks allowlists/stopwords, detect-secrets heuristic filters |

Each added line gets at most one finding. The most specific rule wins, in the
order known format, then keyword, then entropy.

Production tools add two things I left out on purpose. The first is
**verification**: TruffleHog and GitHub's validity checks call the provider's
API to see whether a key is live. The second is **scanning full history**. Both
are out of scope for a ~30-minute CLI.

## Where it fails

I measured noise by running it over the last 300 commits of a large real-world
repo (≈115k added lines). It reported 21 findings. None was a real secret: they
were test-fixture passwords in specs and docs, plus SHA-1 hashes caught by the
hex rule. So expect roughly one false positive per 5k added lines on
test-heavy code.

**False positives**

- **Test fixtures and docs.** `password: "test-password-123"` in a spec looks
  exactly like a real one. The tool doesn't treat test paths specially, because
  real secrets end up in tests too.
- **Hashes and IDs.** SHA-1/SHA-256 digests, git commit hashes and UUIDs without
  dashes pass the hex entropy rule.
- **Key-format lookalikes.** `AKIAFAKEFAKEFAKEFAKE` is reported as an AWS key.
  The format rules check shape, not validity.
- **Comparisons.** `if password == "…"` is reported like an assignment.

**False negatives**

- **No keyword, low entropy.** `connect("db", "admin", "hunter2")` is missed:
  the string is short, not random, and nothing names it as a password.
- **Values with spaces, or split across lines.** Passphrases with spaces,
  multi-line strings, string concatenation, base64-encoded blobs inside other
  encodings.
- **Unquoted values in source code** that look like identifiers (fewer than 3
  digits), e.g. `token = abcdefghij`. This is a deliberate trade-off to avoid
  flagging `token = tokenRepository`. In config files (`.env`, YAML, INI,
  TOML, `.properties`) unquoted values are always treated as literals.
- **Provider formats not on the list.** Only about 10 formats are covered,
  where gitleaks has 150+ and GitHub has 200+. Anything else relies on the
  keyword and entropy rules.
- **One finding per line.** A second secret on the same line is not reported
  separately.
- **Diff scope.** Only added lines are scanned. A secret that was already in the
  file, or that moved in a rename without edits, is not reported. Binary files,
  and untracked files that aren't valid UTF-8, are skipped.
- **Merge commits** are scanned against their first parent only.

## AI usage

Built with Claude Code. The prompts and a log of the decisions are in
[`PROMPTS.md`](PROMPTS.md).
