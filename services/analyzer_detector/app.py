import logging
import os
import time

from flask import Flask, Response, jsonify, request

from common import httpx
from common.config import load_config
from common.metrics import Registry, Timer
from .detector import analyze_item

log = logging.getLogger("analyzer_detector")
RESPONSE_URL = os.getenv("RESPONSE_URL", "http://response-block:8003/decide")
BLOCKLIST_URL = os.getenv("BLOCKLIST_URL", "http://response-block:8003/blocklist")
BLOCKLIST_TTL = float(os.getenv("BLOCKLIST_TTL", "5"))


def _fetch_blocklist():
    import requests
    r = requests.get(BLOCKLIST_URL, timeout=2)
    r.raise_for_status()
    return r.json()


def create_app(post=None, cfg=None, fetch_blocklist=None):
    app = Flask(__name__)
    reg = Registry()
    cfg = cfg or load_config()
    post = post or httpx.post_json
    state = {"t": 0.0}
    reg.describe("detections_total", "Результаты анализа по вердиктам")
    reg.describe("signature_hits_total", "Срабатывания сигнатур")
    reg.describe("detection_latency_seconds", "Время анализа одной единицы содержимого")
    reg.describe("service_health", "1 — сервис работоспособен")
    reg.set("service_health", 1)

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "analyzer_detector"}

    @app.get("/metrics")
    def metrics():
        return Response(reg.render(), mimetype="text/plain; version=0.0.4")

    @app.post("/analyze")
    def analyze():
        item = request.get_json(silent=True) or {}
        if fetch_blocklist is not None and time.time() - state["t"] > BLOCKLIST_TTL:
            try:                                   # синхронизация чёрного списка с response_block
                cfg["blocked_domains"] = list(set(cfg.get("blocked_domains", [])) | set(fetch_blocklist()))
            except Exception as e:
                log.warning("blocklist sync failed: %s", e)
            state["t"] = time.time()
        with Timer(reg, "detection_latency_seconds", kind=item.get("kind", "?")):
            analysis = analyze_item(item, cfg)
        v = analysis["verdict"]["label"]
        reg.inc("detections_total", verdict=v, kind=item.get("kind", "?"))
        for f in analysis["findings"]:
            reg.inc("signature_hits_total", signature=f["id"])
        reg.set("last_score", analysis["verdict"]["score"])
        try:
            result = post(RESPONSE_URL, {"item": item, "analysis": analysis})
        except Exception as e:
            log.error("response_block unavailable: %s", e)
            return jsonify({"decision": "BLOCK", "content": None, "reason": "response_unavailable (fail-closed)",
                            "item_id": item.get("item_id"), "verdict": analysis["verdict"]})
        return jsonify(result)

    return app


app = create_app(fetch_blocklist=_fetch_blocklist)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8002")))
