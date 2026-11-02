"""Ядро обнаружения: сигнатурный и признаковый анализ рекламного и пользовательского содержимого.

Все функции чистые (без сетевого и файлового ввода-вывода), поэтому покрываются модульными тестами.
"""
import html
import math
import re
import time
import urllib.parse
from collections import Counter
from typing import Dict, List

# (идентификатор, регулярное выражение, вес, описание)
SIGNATURES = [
    ("SCRIPT_TAG", r"<\s*script\b", 5, "Элемент <script>"),
    ("EVENT_HANDLER", r"<[^>]+\son[a-z]+\s*=", 5, "Атрибут-обработчик события (onload, onerror, ...)"),
    ("JS_PROTOCOL", r"(?:href|src|action|xlink:href)\s*=\s*[\"']?\s*javascript\s*:", 5, "URL с протоколом javascript:"),
    ("DATA_HTML", r"data\s*:\s*text/html", 4, "URL data:text/html"),
    ("IFRAME", r"<\s*(?:iframe|frame)\b", 3, "Элемент iframe/frame"),
    ("HIDDEN_FRAME", r"<\s*iframe[^>]*(?:width\s*=\s*[\"']?0|height\s*=\s*[\"']?0|display\s*:\s*none|visibility\s*:\s*hidden)", 3,
     "Скрытый iframe"),
    ("OBJECT_EMBED", r"<\s*(?:object|embed|applet)\b", 3, "Элемент object/embed/applet"),
    ("FOREIGN_OBJECT", r"<\s*foreignObject\b", 3, "SVG foreignObject (встраивание HTML в SVG)"),
    ("META_REFRESH", r"<\s*meta[^>]+http-equiv\s*=\s*[\"']?refresh", 3, "Автоматическое перенаправление meta refresh"),
    ("DOC_COOKIE", r"document\s*\.\s*cookie", 5, "Обращение к document.cookie"),
    ("LOCAL_STORAGE", r"(?:local|session)Storage", 2, "Обращение к localStorage/sessionStorage"),
    ("EXFIL_API", r"(?:XMLHttpRequest|\bfetch\s*\(|sendBeacon|new\s+Image\s*\(|\.src\s*=)", 3,
     "Сетевой вызов из скрипта (возможная передача данных)"),
    ("REDIRECT_JS", r"(?:window\s*\.\s*)?location(?:\s*\.\s*(?:href|replace|assign))?\s*(?:=|\()", 3, "Перенаправление из скрипта"),
    ("WINDOW_OPEN", r"window\s*\.\s*open\s*\(", 2, "window.open (всплывающее окно)"),
    ("EVAL_LIKE", r"\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*[\"'a-zA-Z]", 2, "Динамическое выполнение кода"),
    ("DECODE_CALL", r"(?:atob\s*\(|fromCharCode|unescape\s*\()", 3, "Декодирование строк (признак обфускации)"),
    ("HEX_ESCAPES", r"(?:\\x[0-9a-fA-F]{2}){6,}", 3, "Длинные последовательности \\xNN"),
    ("SVG_EXT_REF", r"xlink:href\s*=\s*[\"']\s*https?://", 2, "Внешняя ссылка из SVG"),
    ("STYLE_EXPR", r"(?:expression\s*\(|url\s*\(\s*[\"']?\s*javascript:)", 3, "Исполняемые конструкции в CSS"),
]
_COMPILED = [(i, re.compile(p, re.I | re.S), w, d) for i, p, w, d in SIGNATURES]
NAMESPACE_HOSTS = {"www.w3.org"}
URL_RE = re.compile(r"""(?:https?:)?//[^\s"'<>\)]+""", re.I)


def normalize(content: str) -> str:
    """Приводит содержимое к виду, на котором работают сигнатуры: раскрывает HTML-сущности,
    процентное кодирование, удаляет нулевые символы и разрывы внутри слова javascript:."""
    s = content.replace("\x00", "")
    for _ in range(3):  # многократное раскодирование
        new = html.unescape(s)
        new = urllib.parse.unquote(new) if re.search(r"%[0-9a-fA-F]{2}", new) else new
        if new == s:
            break
        s = new
    s = re.sub(r"(?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", "javascript:", s)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)       # комментарии, разрывающие ключевые слова
    return s


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def extract_urls(content: str) -> List[str]:
    return list(dict.fromkeys(URL_RE.findall(normalize(content))))


def host_of(url: str) -> str:
    u = url if "://" in url else "http:" + url if url.startswith("//") else "http://" + url
    try:
        return (urllib.parse.urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def analyze_url(url: str, cfg: dict) -> List[Dict]:
    """Признаки подозрительного URL (по перечню признаков вредоносных рекламных модулей)."""
    findings = []
    host = host_of(url)
    if host in NAMESPACE_HOSTS:          # URL пространств имён XML/SVG не являются ресурсами
        return findings
    if host in [d.lower() for d in cfg.get("blocked_domains", [])]:
        findings.append({"id": "BLOCKED_DOMAIN", "weight": 6, "desc": f"Домен {host} находится в списке блокировки"})
    if len(url) > 120:
        findings.append({"id": "LONG_URL", "weight": 1, "desc": "Слишком длинный URL"})
    if "@" in url.split("?", 1)[0]:
        findings.append({"id": "AT_IN_URL", "weight": 2, "desc": "Символ @ в URL"})
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""):
        findings.append({"id": "IP_HOST", "weight": 2, "desc": "IP-адрес вместо доменного имени"})
    if host in cfg.get("url_shorteners", []):
        findings.append({"id": "SHORTENER", "weight": 2, "desc": "Сокращатель ссылок"})
    if re.search(r"(?:redirect|url|next|goto|dest)=https?", url, re.I):
        findings.append({"id": "REDIRECT_PARAM", "weight": 1, "desc": "Параметр перенаправления в URL"})
    if url.lower().startswith("http://"):
        findings.append({"id": "NO_TLS", "weight": 1, "desc": "Нешифрованное соединение (HTTP)"})
    trusted = [d.lower() for d in cfg.get("trusted_domains", [])]
    if host and host not in trusted and not host.endswith(tuple("." + t for t in trusted)):
        findings.append({"id": "UNTRUSTED_HOST", "weight": 1, "desc": f"Домен {host} не входит в список доверенных"})
    return findings


def analyze_content(content: str, cfg: dict) -> List[Dict]:
    norm = normalize(content)
    findings = []
    for sid, rx, weight, desc in _COMPILED:
        m = rx.search(norm)
        if m:
            findings.append({"id": sid, "weight": weight, "desc": desc, "evidence": norm[m.start():m.end() + 20][:80]})
    if content != norm and re.search(r"&#x?[0-9a-fA-F]+;|%[0-9a-fA-F]{2}", content) and findings:
        findings.append({"id": "ENCODED_PAYLOAD", "weight": 2, "desc": "Опасные конструкции скрыты кодированием"})
    for tok in re.findall(r"[A-Za-z0-9+/=_-]{60,}", content):
        if shannon_entropy(tok) > 4.5:
            findings.append({"id": "HIGH_ENTROPY", "weight": 2, "desc": "Длинная строка с высокой энтропией"})
            break
    for u in extract_urls(content):
        findings.extend(analyze_url(u, cfg))
    return findings


def check_upload(filename: str, mime: str, content: str, cfg: dict) -> List[Dict]:
    """Проверка файла при загрузке: расширение, MIME-тип, размер и фактическое содержимое."""
    findings = []
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in cfg.get("allowed_upload_types", []):
        findings.append({"id": "EXT_NOT_ALLOWED", "weight": 5, "desc": f"Расширение .{ext} не разрешено"})
    if len(content.encode("utf-8", "ignore")) > cfg.get("max_upload_bytes", 262144):
        findings.append({"id": "TOO_LARGE", "weight": 3, "desc": "Размер файла превышает лимит"})
    head = content.lstrip()[:200].lower()
    actual_svg = head.startswith("<svg") or (head.startswith("<?xml") and "<svg" in content[:1000].lower())
    if ext in ("png", "jpg", "gif") and head.startswith("<"):
        findings.append({"id": "TYPE_MISMATCH", "weight": 4, "desc": "Содержимое не соответствует расширению (разметка вместо изображения)"})
    if ext == "svg" and not actual_svg:
        findings.append({"id": "TYPE_MISMATCH", "weight": 4, "desc": "Файл .svg не содержит корректного корня <svg>"})
    if mime and ext == "svg" and mime not in ("image/svg+xml", "text/xml", "application/xml"):
        findings.append({"id": "MIME_MISMATCH", "weight": 2, "desc": f"MIME-тип {mime} не соответствует SVG"})
    if re.search(r"<!DOCTYPE[^>]*\[|<!ENTITY", content, re.I):
        findings.append({"id": "XML_ENTITY", "weight": 5, "desc": "Объявление XML-сущностей (XXE/«миллиард смехов»)"})
    return findings


def detect_type(content: str, filename: str = "", mime: str = "") -> str:
    head = content.lstrip()[:300].lower()
    if head.startswith("<svg") or (head.startswith("<?xml") and "<svg" in content[:1000].lower()):
        return "svg"
    if "<" in head:
        return "html"
    if filename.endswith(".js") or "javascript" in (mime or ""):
        return "js"
    return "text"


def score_to_verdict(findings: List[Dict], cfg: dict) -> Dict:
    score = sum(f["weight"] for f in findings)
    th = cfg.get("thresholds", {})
    if score >= th.get("block", 5):
        label = "MALICIOUS"
    elif score >= th.get("suspicious", 2):
        label = "SUSPICIOUS"
    else:
        label = "CLEAN"
    return {"label": label, "score": score, "confidence": round(min(1.0, score / 10.0), 2)}


def analyze_item(item: Dict, cfg: dict) -> Dict:
    """Полный анализ единицы содержимого. item: {kind, source, filename, mime, content}."""
    content = item.get("content", "")
    findings = analyze_content(content, cfg)
    if item.get("kind") == "upload":
        findings.extend(check_upload(item.get("filename", ""), item.get("mime", ""), content, cfg))
    src = item.get("source") or ""
    if "://" in src:
        findings.extend(analyze_url(src, cfg))
    uniq, seen = [], set()
    for f in findings:                      # один и тот же признак учитывается один раз
        key = (f["id"], f.get("desc"))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    findings = uniq
    verdict = score_to_verdict(findings, cfg)
    return {"item_id": item.get("item_id"), "verdict": verdict, "findings": findings, "analyzed_at": time.time()}
