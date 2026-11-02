import logging
import os
import time

from flask import Flask, Response, jsonify, request

from common import httpx
from common.config import load_config
from common.metrics import Registry, Timer
from .collector import build_item

log = logging.getLogger("content_collector")
ANALYZER_URL = os.getenv("ANALYZER_URL", "http://analyzer-detector:8002/analyze")


def create_app(post=None):
    app = Flask(__name__)
    reg = Registry()
    reg.describe("collector_items_total", "Количество принятых единиц содержимого")
    reg.describe("collector_errors_total", "Ошибки обработки")
    reg.describe("collector_pipeline_seconds", "Время полного прохождения конвейера")
    post = post or httpx.post_json

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "content_collector"}

    @app.get("/metrics")
    def metrics():
        return Response(reg.render(), mimetype="text/plain; version=0.0.4")

    @app.post("/ingest")
    def ingest():
        payload = request.get_json(silent=True) or {}
        try:
            item = build_item(payload)
        except ValueError as e:
            reg.inc("collector_errors_total", reason="bad_request")
            return jsonify({"error": str(e)}), 400
        reg.inc("collector_items_total", kind=item["kind"], ctype=item["ctype"])
        try:
            with Timer(reg, "collector_pipeline_seconds", kind=item["kind"]):
                result = post(ANALYZER_URL, item)
        except Exception as e:  # fail-closed: при отказе конвейера содержимое НЕ пропускается
            log.error("pipeline failure: %s", e)
            reg.inc("collector_errors_total", reason="pipeline_down")
            return jsonify({"decision": "BLOCK", "content": None, "reason": "pipeline_unavailable (fail-closed)",
                            "item_id": item["item_id"]}), 200
        return jsonify(result)

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8001")))
