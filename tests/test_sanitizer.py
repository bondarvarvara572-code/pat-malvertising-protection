import unittest
from services.response_block.sanitizer import sanitize_html, sanitize_svg

SVG = 'xmlns="http://www.w3.org/2000/svg"'


class TestSvg(unittest.TestCase):
    def test_script_removed(self):
        out = sanitize_svg(f'<svg {SVG}><script>alert(1)</script><circle r="5"/></svg>')
        self.assertNotIn("script", out.lower())
        self.assertIn("circle", out)

    def test_event_attr_removed(self):
        out = sanitize_svg(f'<svg {SVG} onload="alert(1)"><rect width="1" height="1"/></svg>')
        self.assertNotIn("onload", out)

    def test_foreign_object_removed(self):
        out = sanitize_svg(f'<svg {SVG}><foreignObject><p>x</p></foreignObject><rect/></svg>')
        self.assertNotIn("foreignObject", out)

    def test_javascript_href_removed(self):
        out = sanitize_svg(f'<svg {SVG} xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="javascript:alert(1)"/></svg>')
        self.assertNotIn("javascript", out)

    def test_doctype_rejected(self):
        self.assertIsNone(sanitize_svg('<!DOCTYPE svg [<!ENTITY a "b">]><svg/>'))

    def test_not_svg_rejected(self):
        self.assertIsNone(sanitize_svg("<html></html>"))

    def test_broken_xml_rejected(self):
        self.assertIsNone(sanitize_svg("<svg><g></svg>"))

    def test_graphics_preserved(self):
        out = sanitize_svg(f'<svg {SVG} width="10"><path d="M0 0L5 5"/></svg>')
        self.assertIn('d="M0 0L5 5"', out)


class TestHtml(unittest.TestCase):
    def test_script_content_dropped(self):
        self.assertNotIn("alert", sanitize_html("<p>a</p><script>alert(1)</script>"))

    def test_event_attr_dropped(self):
        self.assertNotIn("onclick", sanitize_html('<div onclick="x()">t</div>'))

    def test_js_url_dropped(self):
        self.assertNotIn("javascript", sanitize_html('<a href="javascript:alert(1)">x</a>'))

    def test_https_link_kept_with_rel(self):
        out = sanitize_html('<a href="https://ok.test/">x</a>')
        self.assertIn('href="https://ok.test/"', out)
        self.assertIn("noopener", out)

    def test_text_escaped(self):
        self.assertIn("&lt;b&gt;", sanitize_html("1 &lt;b&gt; 2"))

    def test_iframe_dropped(self):
        self.assertNotIn("iframe", sanitize_html('<iframe src="http://e/"></iframe><p>t</p>'))

    def test_allowed_markup_kept(self):
        self.assertEqual(sanitize_html("<p><b>Привет</b></p>"), "<p><b>Привет</b></p>")


if __name__ == "__main__":
    unittest.main()
