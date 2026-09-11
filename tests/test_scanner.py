import gzip
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secretscan import exit_code, scan, scan_file, scan_line  # noqa: E402


class ScanLineTests(unittest.TestCase):
    def test_password_key_value(self):
        hits = scan_line('2026-09-09 10:00:01 db connect user=app password=Sup3rS3cret!')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["pattern"], "Mot de passe en clair")
        self.assertIn("[MASQUÉ]", hits[0]["excerpt"])
        self.assertNotIn("Sup3rS3cret", hits[0]["excerpt"])

    def test_masked_values_are_ignored(self):
        for line in (
            "password=********",
            "password: [REDACTED]",
            "pwd=<hidden>",
            "password=${DB_PASSWORD}",
        ):
            self.assertEqual(scan_line(line), [], line)

    def test_url_credentials_keep_only_most_severe(self):
        # L'URL et le mot de passe se recouvrent : un seul constat, pas deux.
        hits = scan_line("GET https://admin:hunter22@intranet.example.org/api")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["pattern"], "Identifiants dans une URL")
        self.assertNotIn("hunter22", hits[0]["excerpt"])

    def test_basic_and_bearer(self):
        self.assertEqual(scan_line("Authorization: Basic YWRtaW46c2VjcmV0")[0]["pattern"], "Authentification HTTP Basic")
        self.assertEqual(
            scan_line("authorization=Bearer abcdefghijklmnopqrstuvwxyz0123456789")[0]["pattern"],
            "Jeton Bearer",
        )

    def test_private_key_is_critical(self):
        hits = scan_line("-----BEGIN RSA PRIVATE KEY-----")
        self.assertEqual(hits[0]["severity"], "CRITIQUE")

    def test_aws_and_jwt(self):
        self.assertEqual(scan_line("key AKIAIOSFODNN7EXAMPLE seen")[0]["pattern"], "Clé d'accès AWS")
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.assertEqual(scan_line("token " + jwt)[0]["pattern"], "JWT")

    def test_clean_line(self):
        self.assertEqual(scan_line("2026-09-09 10:00:02 INFO request served in 12 ms"), [])


class ScanFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, content, binary=False):
        path = os.path.join(self.dir, name)
        if name.endswith(".gz"):
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write(content)
        elif binary:
            with open(path, "wb") as handle:
                handle.write(content)
        else:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
        return path

    def test_line_numbers_and_gzip(self):
        self._write("app.log", "ok\nok\npassword=Sup3rS3cret!\n")
        self._write("app.log.2.gz", "Authorization: Basic YWRtaW46c2VjcmV0\n")
        findings = scan([self.dir])
        by_file = {os.path.basename(f["file"]): f for f in findings}
        self.assertEqual(by_file["app.log"]["line"], 3)
        self.assertEqual(by_file["app.log.2.gz"]["pattern"], "Authentification HTTP Basic")

    def test_binary_and_unknown_extensions_are_skipped(self):
        self._write("dump.bin", b"\x00\x01password=Sup3rS3cret!", binary=True)
        self._write("notes.md", "password=Sup3rS3cret!\n")
        self.assertEqual(scan([self.dir]), [])
        # --all inclut les extensions inconnues (mais jamais les binaires)
        findings = scan([self.dir], all_files=True)
        self.assertEqual([os.path.basename(f["file"]) for f in findings], ["notes.md"])

    def test_ignore_regex(self):
        import re

        path = self._write("app.log", "password=Sup3rS3cret! # test fixture\n")
        self.assertEqual(scan_file(path, ignore=re.compile("test fixture")), [])


class ExitCodeTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(exit_code([]), 0)
        self.assertEqual(exit_code([{"severity": "MOYENNE"}]), 1)
        self.assertEqual(exit_code([{"severity": "MOYENNE"}, {"severity": "ÉLEVÉE"}]), 2)
        self.assertEqual(exit_code([{"severity": "CRITIQUE"}]), 2)


if __name__ == "__main__":
    unittest.main()
