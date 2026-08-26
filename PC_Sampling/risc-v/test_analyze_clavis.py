#!/usr/bin/env python3

import tempfile
import unittest
from pathlib import Path

import analyze_clavis as ac


class AnalyzeClavisTests(unittest.TestCase):
    def test_recursive_analysis_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = root / "clavis.cmm"
            helper = root / "sign_helper.cmm"
            entry.write_text(
                "ENTRY &slot\n"
                "&challenge=Data.Long(APB:0x12340000)\n"
                "DO \"&FuncDir/sign_helper.cmm\"\n"
                "Data.Set APB:0x12340004 %Long &response\n"
                "&private_key=0x00112233445566778899AABBCCDDEEFF\n",
                encoding="utf-8",
            )
            helper.write_text(
                "OPEN #1 \"C:/secret/device.key\" /Read\n"
                "READ #1 &response\n"
                "RETURN\n",
                encoding="utf-8",
            )

            report = ac.analyze([entry], [root], recursive=True)
            rendered = ac.render_markdown(report)

            self.assertEqual(len(report.files), 2)
            self.assertTrue(any(d.resolved == "sign_helper.cmm" for d in report.dependencies))
            self.assertIn("target_read", report.category_counts())
            self.assertIn("target_write", report.category_counts())
            self.assertIn("<redacted-sensitive-assignment>", rendered)
            self.assertNotIn("00112233445566778899AABBCCDDEEFF", rendered)
            self.assertNotIn("C:/secret", rendered)
            self.assertIn("<file:device.key>", rendered)

    def test_binary_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clavis.cmm"
            path.write_bytes(b"DO x.cmm\x00secret")
            report = ac.analyze([path], [Path(tmp)], recursive=True)
            self.assertFalse(report.files)
            self.assertTrue(any("NUL byte" in item for item in report.warnings))

    def test_long_hex_is_redacted_but_address_is_kept(self):
        line = "Data.Set APB:0x40000000 %Long 0x0011223344556677"
        safe = ac.sanitize(line)
        self.assertIn("0x40000000", safe)
        self.assertIn("<hex:64bit>", safe)
        self.assertNotIn("0011223344556677", safe)

    def test_report_does_not_publish_absolute_search_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "clavis.cmm"
            path.write_text("RETURN\n", encoding="utf-8")
            report = ac.analyze([path], [root], recursive=True)
            self.assertEqual(report.roots, [root.name])
            self.assertNotIn(str(root.resolve()), ac.render_markdown(report))

    def test_comments_are_not_reported_but_quoted_semicolon_survives(self):
        self.assertEqual(ac.strip_comment("Data.Long(APB:0x10) ; password=oops"),
                         "Data.Long(APB:0x10) ")
        self.assertEqual(ac.strip_comment('OPEN #1 "C:/a;b/file.key" ; comment'),
                         'OPEN #1 "C:/a;b/file.key" ')


if __name__ == "__main__":
    unittest.main()
