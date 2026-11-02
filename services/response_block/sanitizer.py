"""Санитизация SVG и HTML по принципу «белого списка»."""
import re
import xml.etree.ElementTree as ET
from html import escape
from html.parser import HTMLParser
from typing import Optional

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"

SVG_ALLOWED_TAGS = {
    "svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
    "text", "tspan", "linearGradient", "radialGradient", "stop", "clipPath", "mask", "symbol", "use",
}
SVG_BLOCKED_ATTR_VALUE = re.compile(r"(?:javascript|vbscript|data\s*:\s*text/html)", re.I)

HTML_ALLOWED_TAGS = {
    "a", "b", "i", "u", "em", "strong", "p", "br", "div", "span", "img", "ul", "ol", "li", "h1", "h2", "h3", "h4",
    "h5", "h6", "table", "thead", "tbody", "tr", "td", "th", "small", "section", "article",
}
HTML_VOID = {"br", "img"}
HTML_ALLOWED_ATTRS = {"href", "src", "alt", "title", "width", "height", "class"}
HTML_DROP_CONTENT = {"script", "style", "iframe", "object", "embed", "template", "noscript"}
SAFE_URL = re.compile(r"^(?:https?://|/(?!/)|#)", re.I)


def _local(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def sanitize_svg(content: str) -> Optional[str]:
    """Возвращает очищенный SVG либо None, если документ не может быть безопасно разобран."""
    if re.search(r"<!DOCTYPE|<!ENTITY", content, re.I):
        return None
    try:
        ET.register_namespace("", SVG_NS)
        ET.register_namespace("xlink", XLINK_NS)
        root = ET.fromstring(content.strip())
    except ET.ParseError:
        return None
    if _local(root.tag) != "svg":
        return None

    def clean(el):
        for child in list(el):
            name = _local(child.tag)
            if name not in SVG_ALLOWED_TAGS:
                el.remove(child)
                continue
            clean(child)
        for attr in list(el.attrib):
            lname = _local(attr).lower()
            val = el.attrib[attr]
            if lname.startswith("on"):
                del el.attrib[attr]
            elif lname == "href" and not val.startswith("#"):
                del el.attrib[attr]                      # внешние ссылки из SVG запрещены
            elif SVG_BLOCKED_ATTR_VALUE.search(val) or "expression(" in val.lower():
                del el.attrib[attr]

    clean(root)
    return ET.tostring(root, encoding="unicode")


class _HtmlCleaner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.skip_depth = 0
        self.skip_tag = None

    def handle_starttag(self, tag, attrs):
        if self.skip_depth:
            if tag == self.skip_tag:
                self.skip_depth += 1
            return
        if tag in HTML_DROP_CONTENT:
            self.skip_depth, self.skip_tag = 1, tag
            return
        if tag not in HTML_ALLOWED_TAGS:
            return
        safe = []
        for k, v in attrs:
            k = k.lower()
            if k not in HTML_ALLOWED_ATTRS or v is None:
                continue
            if k in ("href", "src") and not SAFE_URL.match(re.sub(r"[\x00-\x20]", "", v)):
                continue
            safe.append(f'{k}="{escape(v, quote=True)}"')
        if tag == "a":
            safe.append('rel="noopener noreferrer nofollow"')
        self.out.append(f"<{tag}{' ' + ' '.join(safe) if safe else ''}>")

    def handle_endtag(self, tag):
        if self.skip_depth:
            if tag == self.skip_tag:
                self.skip_depth -= 1
            return
        if tag in HTML_ALLOWED_TAGS and tag not in HTML_VOID:
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.skip_depth:
            self.out.append(escape(data))


def sanitize_html(content: str) -> str:
    p = _HtmlCleaner()
    p.feed(content)
    p.close()
    return "".join(p.out)
