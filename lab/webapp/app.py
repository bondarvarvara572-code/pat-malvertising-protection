"""Лабораторное веб-приложение. Режим работы задаётся переменной PROTECTION=on|off.

off — уязвимая конфигурация (эксперименты 1–2: атака успешна);
on  — конфигурация с паттерном безопасности (эксперименты 3–4: атака блокируется).
"""
import html
import os
import uuid

import requests
from flask import Flask, Response, abort, jsonify, make_response, redirect, request

AD_URL = os.getenv("AD_URL", "http://localhost:9000")
COLLECTOR_URL = os.getenv("COLLECTOR_URL", "http://localhost:8001/ingest")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/pat_uploads")
TEST_COOKIE = "SESSIONID=TEST-SESSION-12345"      # тестовое значение, не реальные данные

CSP = "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'self'"
FILES_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


def protection_on() -> bool:
    return os.getenv("PROTECTION", "off").lower() == "on"


def create_app():
    app = Flask(__name__)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    @app.after_request
    def headers(resp):
        if protection_on():
            resp.headers.setdefault("Content-Security-Policy", CSP)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    def page(body: str) -> Response:
        doc = ("<!doctype html><meta charset='utf-8'><title>Лабораторное веб-приложение</title>"
               "<h1>Лабораторное веб-приложение</h1>"
               f"<p>Режим защиты: <b>{'ВКЛЮЧЁН' if protection_on() else 'ВЫКЛЮЧЕН (уязвимая конфигурация)'}</b></p>"
               "<nav><a href='/'>Главная</a> · <a href='/upload'>Загрузка</a> · <a href='/gallery'>Галерея</a></nav><hr>" + body)
        resp = make_response(doc)
        resp.set_cookie("SESSIONID", "TEST-SESSION-12345", httponly=False, samesite="Lax")
        return resp

    def fetch_ad(ad_id: str) -> str:
        r = requests.get(f"{AD_URL}/ad/{ad_id}", timeout=3)
        raw = r.text
        if not protection_on():
            return raw                                    # небезопасно: доверие каналу доставки
        res = requests.post(COLLECTOR_URL, json={"kind": "ad", "source": r.headers.get("X-Ad-Origin", f"{AD_URL}/ad/{ad_id}"), "content": raw}, timeout=5).json()
        if res.get("decision") == "BLOCK" or res.get("content") is None:
            return "<div class='ad-blocked'><i>Рекламный блок заблокирован системой защиты</i></div>"
        return res["content"]

    @app.get("/health")
    def health():
        return {"status": "ok", "protection": protection_on()}

    @app.get("/")
    def index():
        ad_id = request.args.get("ad", "1")
        return page(f"<h2>Статья</h2><p>Текст страницы с рекламным блоком.</p><section id='ad-slot'>{fetch_ad(ad_id)}</section>")

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if request.method == "GET":
            return page("<h2>Загрузка изображения</h2><form method='post' enctype='multipart/form-data'>"
                        "<input type='file' name='file'><button>Загрузить</button></form>")
        f = request.files.get("file")
        if not f:
            abort(400)
        raw = f.read().decode("utf-8", "ignore")
        name = os.path.basename(f.filename or "file.bin")
        if protection_on():
            res = requests.post(COLLECTOR_URL, json={"kind": "upload", "source": "user-upload", "filename": name,
                                                      "mime": f.mimetype, "content": raw}, timeout=5).json()
            if res.get("decision") == "BLOCK" or res.get("content") is None:
                return page(f"<p style='color:#b00'>Файл {html.escape(name)} отклонён системой защиты.</p>"), 422
            raw = res["content"]
        stored = f"{uuid.uuid4().hex[:8]}_{name}"
        with open(os.path.join(UPLOAD_DIR, stored), "w", encoding="utf-8") as out:
            out.write(raw)
        return redirect("/gallery")

    @app.get("/gallery")
    def gallery():
        items = sorted(os.listdir(UPLOAD_DIR))
        li = "".join(f"<li><a href='/files/{html.escape(n)}'>{html.escape(n)}</a> "
                     f"<img src='/files/{html.escape(n)}' width='80' alt=''></li>" for n in items)
        return page(f"<h2>Галерея</h2><ul>{li or '<li>пусто</li>'}</ul>")

    @app.get("/files/<name>")
    def files(name):
        path = os.path.join(UPLOAD_DIR, os.path.basename(name))
        if not os.path.exists(path):
            abort(404)
        data = open(path, encoding="utf-8").read()
        mime = "image/svg+xml" if name.lower().endswith(".svg") else "text/plain"
        resp = Response(data, mimetype=mime)
        if protection_on():
            resp.headers["Content-Security-Policy"] = FILES_CSP   # изоляция пользовательских файлов
            resp.headers["Content-Disposition"] = "inline"
        return resp

    @app.post("/admin/reset")
    def reset():
        for n in os.listdir(UPLOAD_DIR):
            os.remove(os.path.join(UPLOAD_DIR, n))
        return {"ok": True}

    return app


app = create_app()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
