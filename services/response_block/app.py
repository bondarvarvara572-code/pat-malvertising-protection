import logging
import os

from flask import Flask, Response, jsonify, request

from common import httpx
from common.config import load_config
from common.metrics import Registry, Timer
from .policy import Blocklist, decide

log = logging.getLogger("response_block")
ALERT_URL = os.getenv("ALERT_URL", "http://visual-alert:8004/event")


def create_app(post=None, cfg=None):
    app = Flask(__name__)
    reg = Registry()
    cfg = cfg or load_config()
    blocklist = Blocklist(cfg.get("blocked_domains", []))
    post = post or httpx.post_json
    reg.describe("decisions_total", "Принятые решения")
    reg.describe("blocklist_size", "Размер динамического чёрного списка доменов")
    reg.describe("response_latency_seconds", "Время принятия решения и санитизации")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "response_block"}

    @app.get("/metrics")
    def metrics():
        return Response(reg.render(), mimetype="text/plain; version=0.0.4")

    @app.get("/blocklist")
    def get_blocklist():
        return jsonify(blocklist.as_list())

    @app.post("/decide")
    def decide_ep():
        data = request.get_json(silent=True) or {}
        item, analysis = data.get("item", {}), data.get("analysis", {})
        with Timer(reg, "response_latency_seconds"):
            res = decide(item, analysis, cfg, blocklist)
        reg.inc("decisions_total", decision=res["decision"], kind=item.get("kind", "?"))
        reg.set("blocklist_size", len(blocklist.as_list()))
        event = {
            "item_id": item.get("item_id"), "kind": item.get("kind"), "source": item.get("source"),
            "ctype": item.get("ctype"), "sha256": item.get("sha256"), "filename": item.get("filename"),
            "verdict": analysis.get("verdict", {}), "findings": analysis.get("findings", []),
            "decision": res["decision"], "actions": res["actions"],
        }
        try:
            post(ALERT_URL, event)
        except Exception as e:
            log.error("visual_alert unavailable: %s", e)
        return jsonify({"item_id": item.get("item_id"), "decision": res["decision"], "content": res["content"],
                        "verdict": analysis.get("verdict"), "actions": res["actions"]})

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8003")))
