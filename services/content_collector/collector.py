"""Нормализация входящего содержимого: идентификатор, хэш, тип, источник, список URL."""
import hashlib
import time
import uuid
from typing import Dict

from services.analyzer_detector.detector import detect_type, extract_urls, host_of

VALID_KINDS = {"ad", "upload", "service"}


def build_item(payload: Dict) -> Dict:
    kind = payload.get("kind", "ad")
    if kind not in VALID_KINDS:
        raise ValueError(f"unknown kind: {kind}")
    content = payload.get("content", "")
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    filename = payload.get("filename", "")
    mime = payload.get("mime", "")
    return {
        "item_id": uuid.uuid4().hex[:12],
        "kind": kind,
        "source": payload.get("source", ""),
        "source_host": host_of(payload.get("source", "")),
        "filename": filename,
        "mime": mime,
        "ctype": detect_type(content, filename, mime),
        "size": len(content.encode("utf-8", "ignore")),
        "sha256": hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest(),
        "urls": extract_urls(content),
        "content": content,
        "received_at": time.time(),
    }
