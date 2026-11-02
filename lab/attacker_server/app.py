"""Сервер «атакующего» для лабораторных экспериментов: фиксирует факт получения тестовых данных.
Реальные данные не обрабатываются: используется только тестовое значение cookie."""
import os
import time

from flask import Flask, Response, jsonify, request

STOLEN = []


def create_app():
    app = Flask(__name__)

    @app.after_request
    def cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @app.get("/steal")
    def steal():
        STOLEN.append({"ts": time.strftime("%H:%M:%S"), "cookie": request.args.get("c"), "ip": request.remote_addr,
                       "ua": request.headers.get("User-Agent", "")[:60]})
        print(f"[ATTACKER] получено: {request.args.get('c')}", flush=True)
        return Response("", status=204)

    @app.get("/log")
    def log():
        return jsonify(STOLEN)

    @app.post("/reset")
    def reset():
        STOLEN.clear()
        return {"ok": True}

    @app.get("/landing")
    def landing():
        return "attacker landing"

    @app.get("/phish")
    def phish():
        STOLEN.append({"ts": time.strftime("%H:%M:%S"), "cookie": "REDIRECT", "ip": request.remote_addr, "ua": ""})
        return "attacker phishing page (учебная заглушка)"

    @app.get("/")
    def index():
        rows = "".join(f"<tr><td>{s['ts']}</td><td>{s['cookie']}</td></tr>" for s in STOLEN)
        return Response("<meta charset='utf-8'><h2>Сервер атакующего: журнал</h2><table border=1>" + rows + "</table>", mimetype="text/html")

    return app


app = create_app()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "9999")))
