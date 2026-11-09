"""Tests for secret_finder. Run: python3 -m unittest -v

All "secrets" below are fake. Token-shaped values are assembled at runtime so the
literal never sits in this file (keeps GitHub push protection and our own scanner quiet).
"""
import os
import subprocess
import sys
import tempfile
import unittest

from secret_finder import added_lines, scan_diff, scan_line

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_AWS = "AKIA" + "FAKE" * 4
FAKE_GH = "ghp_" + "Fa1ke" * 7 + "X"
FAKE_RANDOM = "q8Vz" + "Lp3RwX9kTm2Yb7NcJ4fHs6Gd"  # 28 chars, ~4.7 bits/char


class DiffParsingTest(unittest.TestCase):
    def test_only_added_lines_with_new_file_line_numbers(self):
        diff = f"""\
diff --git a/app/config.py b/app/config.py
index 1111111..2222222 100644
--- a/app/config.py
+++ b/app/config.py
@@ -10,4 +10,5 @@ import os
 DEBUG = False
-OLD_KEY = "{FAKE_AWS}"
+AWS_KEY = "{FAKE_AWS}"
+REGION = "eu-west-1"
 TIMEOUT = 30
+db_password = "s3cr3t-Hunter2!"
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-password = "deleted-lines-are-ignored"
""".splitlines()

        self.assertEqual(
            [(p, n) for p, n, _ in added_lines(diff)],
            [("app/config.py", 11), ("app/config.py", 12), ("app/config.py", 14)],
        )
        findings = scan_diff(diff)
        self.assertEqual(
            [(f.path, f.line, f.rule) for f in findings],
            [("app/config.py", 11, "aws-access-key-id"),
             ("app/config.py", 14, "keyword-assignment")],
        )


class DetectorTest(unittest.TestCase):
    def assertFinds(self, line, rule):
        finding = scan_line("f", 1, line)
        self.assertIsNotNone(finding, f"expected {rule} in {line!r}")
        self.assertEqual(finding.rule, rule)

    def assertClean(self, line):
        self.assertIsNone(scan_line("f", 1, line), f"false positive on {line!r}")

    def test_true_positives(self):
        self.assertFinds(f'token = "{FAKE_GH}"', "github-token")
        self.assertFinds("-----BEGIN RSA PRIVATE KEY-----", "private-key")
        self.assertFinds("DATABASE_URL=postgres://admin:Sup3rS3cret@db.local:5432/app", "url-credentials")
        self.assertFinds('"password": "correct-horse-battery"', "keyword-assignment")
        self.assertFinds(f"API_KEY={FAKE_RANDOM}", "keyword-assignment")
        self.assertFinds(f'headers = {{"X-Custom": "{FAKE_RANDOM}"}}', "high-entropy-string")

    def test_common_false_positives_are_ignored(self):
        self.assertClean('password = os.environ["DB_PASSWORD"]')
        self.assertClean("password = getpass.getpass()")
        self.assertClean('api_key = "${API_KEY}"')
        self.assertClean('secret = "your-secret-here"')
        self.assertClean('password = "changeme"')
        self.assertClean("token = settings.GITHUB_TOKEN")
        self.assertClean("def validate_password(password: str) -> bool:")
        self.assertClean('logger.info("Successfully connected to the database")')
        self.assertClean(f'aws_key = "{FAKE_AWS}"  # pragma: allowlist secret')


class GitIntegrationTest(unittest.TestCase):
    """End to end through the CLI: commit hash, working tree and stdin inputs."""

    def run_cli(self, *args, cwd, stdin=None):
        return subprocess.run([sys.executable, os.path.join(HERE, "secret_finder.py"), *args],
                              cwd=cwd, input=stdin, capture_output=True, text=True)

    def test_commit_working_tree_and_stdin(self):
        with tempfile.TemporaryDirectory() as repo:
            def git(*a):
                subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                                "-c", "commit.gpgsign=false", *a],
                               cwd=repo, check=True, capture_output=True)

            git("init", "-q")
            with open(os.path.join(repo, "settings.py"), "w") as f:
                f.write("DEBUG = True\n")
            git("add", ".")
            git("commit", "-q", "-m", "clean")

            # Clean commit, clean tree -> exit 0.
            self.assertEqual(self.run_cli("--commit", "HEAD", cwd=repo).returncode, 0)

            with open(os.path.join(repo, "settings.py"), "a") as f:
                f.write(f'AWS_ACCESS_KEY_ID = "{FAKE_AWS}"\n')
            with open(os.path.join(repo, "new_untracked.env"), "w") as f:
                f.write("SMTP_PASSWORD=hunter2hunter2\n")

            # Working tree (unstaged + untracked).
            result = self.run_cli(cwd=repo)
            self.assertEqual(result.returncode, 1)
            self.assertIn("settings.py:2: [aws-access-key-id]", result.stdout)
            self.assertIn("new_untracked.env:1: [keyword-assignment]", result.stdout)
            self.assertNotIn(FAKE_AWS, result.stdout, "output must redact the secret")

            # Commit hash.
            git("add", ".")
            git("commit", "-q", "-m", "oops")
            result = self.run_cli("--commit", "HEAD", cwd=repo)
            self.assertEqual(result.returncode, 1)
            self.assertIn("settings.py:2: [aws-access-key-id]", result.stdout)

            # Diff on stdin.
            diff = subprocess.run(["git", "show", "HEAD"], cwd=repo,
                                  capture_output=True, text=True).stdout
            result = self.run_cli("--diff", "-", cwd=repo, stdin=diff)
            self.assertEqual(result.returncode, 1)
            self.assertIn("new_untracked.env:1:", result.stdout)


if __name__ == "__main__":
    unittest.main()
