# AI prompts and log

Built with **Claude Code** (desktop app, Claude Opus 5.5). The repo includes an
[`AGENTS.md`](AGENTS.md) with the brief and ground rules for the agent: keep it
small, scan only added lines, use fake fixtures, exit non-zero on findings.
The log below is in order.

## Session 1: research and implementation (2026-11-09)

### Prompt

> let's implement this. check how existing production systems like github
> secret scanner etc work. if you can't find code, check open-source
> alternatives. it must already be a quite mature idea

### What the agent did

1. **Read the brief** (`challenge.txt`) and chose **Python, stdlib only**:
   Python 3 is available everywhere and needs no install step.

2. **Researched existing tools.** A sub-agent read these sources:
   - **gitleaks** `config/gitleaks.toml`: per-provider regexes such as
     `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b` for AWS, plus a
     `generic-api-key` rule (keyword + assignment operator + value, entropy
     ≥ 3.5), keyword pre-filters, and allowlists by path, regex and stopword.
   - **GitHub secret scanning** docs: provider/partner patterns, generic
     patterns (private keys, connection strings), validity checks against the
     issuer, and AI detection for unstructured passwords.
   - **TruffleHog**: detectors plus *verification*, which calls the provider's
     API to tell whether a credential is live.
   - **detect-secrets** (Yelp): the page fetch failed, so these details come
     from the model's knowledge. Base64 and hex entropy plugins with default
     limits of 4.5 and 3.0 bits/char, a KeywordDetector, and the
     `pragma: allowlist secret` inline comment.

   **Conclusion:** every mature tool uses the same three layers (known
   formats, keyword assignments, entropy) plus allowlists to control noise.
   I implemented those layers with a small rule set. Verification and
   full-history scanning stay out of scope.

3. **Implemented `secret_finder.py`:**
   - A unified-diff parser that tracks `+++ b/path` and the `@@ … +N,M @@`
     hunk headers to get **new-file line numbers**. Only `+` lines are yielded.
   - Three inputs: `--diff FILE|-`, `--commit REV` (`git show`, first-parent
     for merges), and the default working-tree mode (`git diff HEAD` plus
     untracked files, falling back to the empty tree in a repo with no
     commits yet).
   - Output is `file:line: [rule] reason (redacted)`, so the tool doesn't
     re-leak the secret in CI logs. Exit 1 on findings, 2 on errors.

4. **Tests (`test_secret_finder.py`)**: diff parsing and line numbers, detector
   true positives and common false positives, and an end-to-end test against a
   temporary git repo covering all three inputs. Token-shaped fixtures are
   assembled at runtime (`"AKIA" + "FAKE" * 4`), so no secret-looking literal
   is committed. This keeps GitHub push protection quiet on the public repo.

### Iterations driven by real data

- **Test failure:** `SMTP_PASSWORD=hunter2hunter2` in an untracked `.env`
  was missed. Unquoted values had to pass the entropy check, and this one
  didn't. **Fix:** in config files (`.env`, YAML, INI, TOML, `.properties`),
  unquoted values are treated as literals.
- **Noise check:** I ran the tool over the last 300 commits of a large local
  open-source repo (≈115k added lines). I inspected the results with values
  redacted to their *shape* (e.g. `aAaA9`), never printed raw. The auto-mode
  safety classifier blocked a first attempt that would have printed the raw
  flagged lines. That was the right call, and redacted shapes were enough.
  Fixes:
  - `${REDIS_PASSWORD:-default}` (compose interpolation) was flagged. Values
    containing `${`, starting with `-` or ending with `}` are now ignored.
  - Lockfile integrity hashes were flagged. Lockfiles and binary extensions
    are now skipped by path.
  - `x = calendarSubscriptionTokenStoreRepository`: camelCase identifiers have
    high entropy. Unquoted identifier-shaped values with fewer than 3 digits
    are no longer flagged in source code. File paths and `(...)` calls are
    ignored too.
  - Result: 21 findings, all test fixtures or SHA-1 hashes. These are
    documented as known false positives in the README.
- **Exit codes:** git failures used to exit 1, which looked like "secrets
  found". They now exit 2 with a single-line error.

### Self-scan

Running the tool on its own files flags the test fixtures and the brief's
example key `AKIAFAKEFAKEFAKEFAKE` in `AGENTS.md`. This is expected: format
rules check shape, not validity. It's listed under false positives in the
README.
