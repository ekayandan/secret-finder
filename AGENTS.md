# AGENTS.md

Context and rules for AI agents working in this repository.

## What this is

A take-home challenge for an **AI-Native Software Engineer** application. The full
brief is in [`challenge.txt`](challenge.txt) (converted from the original PDF).
Target effort: **about 30 minutes**. Keep the solution small, readable, and easy to
explain. The author may be asked to walk through it later.

## The task: Secret Finder

Build a **CLI tool** that finds passwords and keys committed by mistake in a change.

- **Input** (all three should work):
  - a git diff, from a file or stdin
  - a commit hash
  - the current changes in the working directory
- **Output**: a list of findings, each with **file**, **line**, and a **short reason**.

## Hard requirements

- Start from scratch. CLI only, no web UI or service.
- Any language and tooling is allowed, AI included.
- Include a **short README** that covers:
  - how to run it
  - **where it fails**: known limitations, false positives and negatives
- Include **2-3 tests**.
- **Include the AI prompts and logs** used to build it. Keep a running log in the
  repo, e.g. `PROMPTS.md` or an `ai-logs/` folder, and append to it as work happens.

## Submission

- The code goes in a **new public GitHub repository**, built from scratch.
- The author replies to the recruiter's email with the repo link. Agents do not
  send email.
- Because the repo is public, never commit real secrets, personal data, or private
  correspondence. Test fixtures must use obviously fake values, e.g.
  `AKIAFAKEFAKEFAKEFAKE`.

## Guidance for agents

- Favor simplicity over coverage. A handful of well-chosen detectors (known key
  formats, high-entropy strings, `password=`/`secret=`/`token=` assignments, private
  key headers) beats a sprawling rule set.
- Only scan **added lines** (`+`) in the diff, and report line numbers in the new file.
- Keep dependencies minimal, so it runs with a single obvious command.
- Use a non-zero exit code when findings exist. That makes it usable as a pre-commit
  or CI check.
- Don't commit or push unless the author asks.
