"""Тонкая обёртка над requests для обмена JSON между микросервисами."""
import logging

import requests

log = logging.getLogger("common.http")


def post_json(url: str, payload: dict, timeout: float = 5.0) -> dict:
    """Отправляет JSON и возвращает JSON-ответ. При ошибке бросает исключение."""
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()
