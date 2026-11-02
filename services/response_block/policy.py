"""Политика принятия решения: ALLOW / SANITIZE / BLOCK."""
from typing import Dict, Optional
import re

from services.analyzer_detector.detector import analyze_content, check_upload, score_to_verdict, host_of
from .sanitizer import sanitize_html, sanitize_svg


# Структурные нарушения при загрузке файла: такие файлы не «лечатся», а отклоняются
STRUCTURAL = {"EXT_NOT_ALLOWED", "TYPE_MISMATCH", "XML_ENTITY", "TOO_LARGE", "MIME_MISMATCH"}


class Blocklist:
    """Динамический чёрный список доменов (пополняется при обнаружении угроз)."""
    def __init__(self, initial=None):
        self._d = set(d.lower() for d in (initial or []))

    def add(self, domain: str) -> bool:
        domain = (domain or "").lower()
        if domain and domain not in self._d:
            self._d.add(domain)
            return True
        return False

    def __contains__(self, d):
        return (d or "").lower() in self._d

    def as_list(self):
        return sorted(self._d)


def decide(item: Dict, analysis: Dict, cfg: dict, blocklist: Blocklist) -> Dict:
    """Возвращает решение и (при необходимости) очищенное содержимое.

    Правила:
      CLEAN       -> ALLOW (содержимое передаётся без изменений);
      SUSPICIOUS  -> SANITIZE для svg/html; после очистки выполняется повторный анализ;
                     если остаточный балл >= порога блокировки, то BLOCK;
      MALICIOUS   -> BLOCK, домен источника добавляется в чёрный список (для рекламы).
    """
    label = analysis["verdict"]["label"]
    ctype = item.get("ctype", "text")
    actions = []
    result = {"decision": "ALLOW", "content": item.get("content"), "actions": actions}

    if label == "CLEAN":
        return result

    ids = {f["id"] for f in analysis.get("findings", [])}
    # Пользовательский SVG с активным содержимым, но без структурных нарушений, очищается, а не отклоняется
    repairable_upload = (label == "MALICIOUS" and item.get("kind") == "upload" and ctype == "svg" and not (ids & STRUCTURAL))
    if label == "MALICIOUS" and not repairable_upload:
        result.update(decision="BLOCK", content=None)
        actions.append("content_withheld")
    else:  # SUSPICIOUS (или восстановимый MALICIOUS-файл)
        cleaned: Optional[str] = None
        if ctype == "svg":
            cleaned = sanitize_svg(item["content"])
        elif ctype == "html":
            cleaned = sanitize_html(item["content"])
        if cleaned is None:
            result.update(decision="BLOCK", content=None)
            actions.append("content_withheld")
        else:
            residual = score_to_verdict(analyze_content(cleaned, cfg), cfg)
            if residual["label"] != "CLEAN" and residual["score"] >= cfg["thresholds"]["block"]:
                result.update(decision="BLOCK", content=None)
                actions.append("content_withheld")
            else:
                result.update(decision="SANITIZE", content=cleaned)
                actions.append("sanitized")

    if result["decision"] == "BLOCK" and item.get("kind") == "ad":
        host = host_of(item.get("source", ""))
        if host and blocklist.add(host):
            actions.append(f"domain_blocklisted:{host}")
    return result
