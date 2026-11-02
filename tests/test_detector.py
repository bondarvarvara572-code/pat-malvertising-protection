import unittest
from services.analyzer_detector import detector as d
from common.config import DEFAULT
import copy

CFG = copy.deepcopy(DEFAULT)


class TestSignatures(unittest.TestCase):
    def label(self, html, **kw):
        item = {"kind": "ad", "source": "https://ads.partner-trusted.local/a", "content": html}
        item.update(kw)
        return d.analyze_item(item, CFG)["verdict"]["label"]

    def test_script_tag_malicious(self):
        self.assertEqual(self.label("<script>alert(1)</script>"), "MALICIOUS")

    def test_event_handler_malicious(self):
        self.assertEqual(self.label('<img src=x onerror="alert(1)">'), "MALICIOUS")

    def test_javascript_protocol_malicious(self):
        self.assertEqual(self.label('<a href="javascript:alert(1)">x</a>'), "MALICIOUS")

    def test_entity_encoded_javascript_detected(self):
        self.assertEqual(self.label('<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>'), "MALICIOUS")

    def test_tab_split_javascript_detected(self):
        self.assertEqual(self.label('<a href="java\tscript:alert(1)">x</a>'), "MALICIOUS")

    def test_hidden_iframe_malicious(self):
        self.assertEqual(self.label('<iframe src="http://evil.test/" width="0" height="0"></iframe>'), "MALICIOUS")

    def test_benign_ad_clean(self):
        self.assertEqual(self.label('<div><a href="https://ads.partner-trusted.local/p"><b>Скидка</b></a></div>'), "CLEAN")

    def test_plain_text_clean(self):
        self.assertEqual(self.label("Обычный текст рекламного блока"), "CLEAN")

    def test_cookie_access_alone_is_malicious(self):
        self.assertEqual(self.label("document.cookie"), "MALICIOUS")


class TestUrl(unittest.TestCase):
    def ids(self, url):
        return {f["id"] for f in d.analyze_url(url, CFG)}

    def test_ip_host(self):
        self.assertIn("IP_HOST", self.ids("http://203.0.113.7/pay"))

    def test_at_symbol(self):
        self.assertIn("AT_IN_URL", self.ids("http://good.example@evil.test/x"))

    def test_shortener(self):
        self.assertIn("SHORTENER", self.ids("https://bit.ly/abc"))

    def test_long_url(self):
        self.assertIn("LONG_URL", self.ids("https://ads.partner-trusted.local/" + "a" * 130))

    def test_trusted_host_no_untrusted_flag(self):
        self.assertNotIn("UNTRUSTED_HOST", self.ids("https://ads.partner-trusted.local/x"))

    def test_blocked_domain(self):
        cfg = copy.deepcopy(CFG)
        cfg["blocked_domains"] = ["evil.test"]
        ids = {f["id"] for f in d.analyze_url("https://evil.test/x", cfg)}
        self.assertIn("BLOCKED_DOMAIN", ids)


class TestUpload(unittest.TestCase):
    def ids(self, name, mime, content):
        return {f["id"] for f in d.check_upload(name, mime, content, CFG)}

    def test_disallowed_extension(self):
        self.assertIn("EXT_NOT_ALLOWED", self.ids("a.html", "text/html", "<p>x</p>"))

    def test_html_as_png(self):
        self.assertIn("TYPE_MISMATCH", self.ids("a.png", "image/png", "<html></html>"))

    def test_svg_ok(self):
        self.assertEqual(self.ids("a.svg", "image/svg+xml", '<svg xmlns="http://www.w3.org/2000/svg"/>'), set())

    def test_xml_entity(self):
        self.assertIn("XML_ENTITY", self.ids("a.svg", "image/svg+xml", '<!DOCTYPE svg [<!ENTITY a "b">]><svg/>'))

    def test_size_limit(self):
        self.assertIn("TOO_LARGE", self.ids("a.txt", "text/plain", "x" * (CFG["max_upload_bytes"] + 1)))


class TestHelpers(unittest.TestCase):
    def test_entropy_range(self):
        self.assertAlmostEqual(d.shannon_entropy("aaaa"), 0.0)
        self.assertGreater(d.shannon_entropy("abcdefgh"), 2.9)

    def test_detect_type(self):
        self.assertEqual(d.detect_type('<svg xmlns="x"/>'), "svg")
        self.assertEqual(d.detect_type("<div>1</div>"), "html")
        self.assertEqual(d.detect_type("hello"), "text")

    def test_verdict_thresholds(self):
        self.assertEqual(d.score_to_verdict([], CFG)["label"], "CLEAN")
        self.assertEqual(d.score_to_verdict([{"weight": 2}], CFG)["label"], "SUSPICIOUS")
        self.assertEqual(d.score_to_verdict([{"weight": 5}], CFG)["label"], "MALICIOUS")


if __name__ == "__main__":
    unittest.main()
