import html
import logging
import os

import requests
from flask import Flask, Response, jsonify, request

from common.metrics import Registry
from .store import EventStore, format_alert

log = logging.getLogger("visual_alert")


def send_telegram(text: str):
    token, chat = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return False
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={"chat_id": chat, "text": text}, timeout=5)
        return r.ok
    except Exception as e:  # сбой канала оповещения не должен ломать конвейер
        log.error("telegram failed: %s", e)
        return False


def create_app(store=None, notifier=send_telegram):
    app = Flask(__name__)
    store = store or EventStore(os.getenv("EVENTS_DB", ":memory:"))
    reg = Registry()
    reg.describe("events_total", "Зарегистрированные события безопасности")
    reg.describe("alerts_sent_total", "Отправленные оповещения")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "visual_alert"}

    @app.get("/metrics")
    def metrics():
        for dec, c in store.counts().items():
            reg.set("events_by_decision", c, decision=dec)
        return Response(reg.render(), mimetype="text/plain; version=0.0.4")

    @app.post("/event")
    def event():
        ev = request.get_json(silent=True) or {}
        eid = store.add(ev)
        reg.inc("events_total", decision=ev.get("decision", "?"))
        text = format_alert(ev)
        log.warning("ALERT\n%s", text) if ev.get("decision") != "ALLOW" else None
        if ev.get("decision") in ("BLOCK", "SANITIZE") and notifier(text):
            reg.inc("alerts_sent_total", channel="telegram")
        return jsonify({"stored": eid})

    @app.get("/events")
    def events():
        return jsonify(store.last(int(request.args.get("n", 50))))

    @app.get("/")
    def dashboard():
        rows = "".join(
            f"<tr class='{html.escape(e['decision'] or '')}'><td>{e['id']}</td><td>{html.escape(str(e['kind']))}</td>"
            f"<td>{html.escape(str(e['source'] or e['filename'] or ''))}</td><td>{html.escape(str(e['ctype']))}</td>"
            f"<td>{html.escape(str(e['label']))} ({e['score']})</td><td><b>{html.escape(str(e['decision']))}</b></td>"
            f"<td>{html.escape(', '.join(e['findings']))}</td><td>{html.escape(', '.join(e['actions']))}</td></tr>"
            for e in store.last(100))
        page = ("<!doctype html><meta charset='utf-8'><title>Журнал безопасности</title>"
                "<style>body{font:14px sans-serif;margin:20px}table{border-collapse:collapse;width:100%}"
                "td,th{border:1px solid #bbb;padding:4px 8px}tr.BLOCK{background:#fde2e2}tr.SANITIZE{background:#fff3cd}"
                "tr.ALLOW{background:#e6f4ea}</style><h2>Журнал событий безопасности</h2>"
                "<table><tr><th>#</th><th>Канал</th><th>Источник</th><th>Тип</th><th>Вердикт</th><th>Решение</th>"
                "<th>Признаки</th><th>Действия</th></tr>" + rows + "</table>")
        return Response(page, mimetype="text/html")

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8004")))
