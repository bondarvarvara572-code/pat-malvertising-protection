"""Загрузка единой конфигурации паттерна (config/pattern_config.json)."""
import json
import os

DEFAULT = {
    "trusted_domains": ["cdn.example-trusted.local", "ads.partner-trusted.local"],
    "blocked_domains": [],
    "url_shorteners": ["bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly"],
    "thresholds": {"suspicious": 2, "block": 5},
    "max_upload_bytes": 262144,
    "allowed_upload_types": ["svg", "png", "jpg", "gif", "txt"],
}


def load_config(path: str = None) -> dict:
    path = path or os.getenv("PATTERN_CONFIG", "/app/config/pattern_config.json")
    cfg = json.loads(json.dumps(DEFAULT))
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return cfg
