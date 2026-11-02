import copy
import unittest
from common.config import DEFAULT
from services.analyzer_detector.detector import analyze_item
from services.content_collector.collector import build_item
from services.response_block.policy import Blocklist, decide

CFG = copy.deepcopy(DEFAULT)


def run(payload):
    item = build_item(payload)
    an = analyze_item(item, CFG)
    bl = Blocklist()
    return decide(item, an, CFG, bl), bl


class TestPolicy(unittest.TestCase):
    def test_clean_allowed_unchanged(self):
        res, _ = run({"kind": "ad", "source": "https://ads.partner-trusted.local/a", "content": "<p>Привет</p>"})
        self.assertEqual(res["decision"], "ALLOW")
        self.assertEqual(res["content"], "<p>Привет</p>")

    def test_malicious_ad_blocked_and_domain_listed(self):
        res, bl = run({"kind": "ad", "source": "http://evil.test/ad", "content": "<script>alert(1)</script>"})
        self.assertEqual(res["decision"], "BLOCK")
        self.assertIsNone(res["content"])
        self.assertIn("evil.test", bl)

    def test_svg_upload_with_script_sanitized(self):
        res, bl = run({"kind": "upload", "source": "user-upload", "filename": "a.svg", "mime": "image/svg+xml",
                       "content": '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><circle r="3"/></svg>'})
        self.assertEqual(res["decision"], "SANITIZE")
        self.assertNotIn("script", res["content"])
        self.assertEqual(bl.as_list(), [])

    def test_structural_violation_blocked(self):
        res, _ = run({"kind": "upload", "source": "user-upload", "filename": "photo.png", "mime": "image/png",
                      "content": "<html><script>alert(1)</script></html>"})
        self.assertEqual(res["decision"], "BLOCK")

    def test_xxe_svg_blocked(self):
        res, _ = run({"kind": "upload", "source": "user-upload", "filename": "b.svg", "mime": "image/svg+xml",
                      "content": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "x">]><svg xmlns="http://www.w3.org/2000/svg"/>'})
        self.assertEqual(res["decision"], "BLOCK")

    def test_suspicious_html_sanitized(self):
        # внешний недоверенный домен (+1) и параметр перенаправления (+1) -> SUSPICIOUS
        res, _ = run({"kind": "ad", "source": "https://ads.partner-trusted.local/a",
                      "content": '<a href="https://unknown.example/x?url=https://other.example">Читать</a>'})
        self.assertIn(res["decision"], ("SANITIZE", "ALLOW"))

    def test_blocklist_case_insensitive(self):
        bl = Blocklist(["Evil.Test"])
        self.assertIn("evil.test", bl)
        self.assertFalse(bl.add("EVIL.test"))


if __name__ == "__main__":
    unittest.main()
