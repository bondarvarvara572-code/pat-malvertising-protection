"""Оценка качества работы паттерна на тестовом корпусе. Запуск: python scripts/evaluate_corpus.py
Результат печатается в консоль и сохраняется в results/evaluation.json."""
import copy
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.config import load_config
from services.analyzer_detector.app import create_app as mk_analyzer
from services.analyzer_detector.detector import analyze_content
from services.content_collector.app import create_app as mk_collector
from services.response_block.app import create_app as mk_response
from services.visual_alert.app import create_app as mk_alert
from services.visual_alert.store import EventStore
from tests import corpus as C


def build():
    cfg = load_config(os.path.join(os.path.dirname(__file__), "..", "config", "pattern_config.json"))
    store = EventStore(":memory:")
    alert = mk_alert(store=store, notifier=lambda t: True).test_client()
    resp = mk_response(post=lambda u, p: alert.post("/event", json=p).get_json(), cfg=copy.deepcopy(cfg)).test_client()
    ana = mk_analyzer(post=lambda u, p: resp.post("/decide", json=p).get_json(), cfg=copy.deepcopy(cfg)).test_client()
    col = mk_collector(post=lambda u, p: ana.post("/analyze", json=p).get_json()).test_client()
    return col, cfg, store


def neutralized(result, cfg):
    if result["decision"] == "BLOCK":
        return True
    if result["decision"] == "SANITIZE":
        residual = [f for f in analyze_content(result["content"], cfg) if f["weight"] >= 3]
        return not residual
    return False


def main():
    logs = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}
    rows = []
    lat = []
    for group, items, malicious in (("Реклама: безопасная", C.BENIGN_ADS, False), ("Реклама: вредоносная", C.MALICIOUS_ADS, True),
                                    ("Реклама: обход сигнатур", C.EVASION_ADS, True)):
        for name, html in items:
            col, cfg, _ = build()
            t0 = time.perf_counter()
            r = col.post("/ingest", json={"kind": "ad", "source": "https://ads.partner-trusted.local/x", "content": html}).get_json()
            lat.append((time.perf_counter() - t0) * 1000)
            ok = neutralized(r, cfg) if malicious else (r["decision"] == "ALLOW")
            rows.append((group, name, r["decision"], r["verdict"]["label"], r["verdict"]["score"], ok))
    for group, items, malicious in (("Файлы: безопасные", C.BENIGN_UPLOADS, False), ("Файлы: вредоносные", C.MALICIOUS_UPLOADS, True)):
        for name, fn, mime, content in items:
            col, cfg, _ = build()
            t0 = time.perf_counter()
            r = col.post("/ingest", json={"kind": "upload", "source": "user-upload", "filename": fn, "mime": mime, "content": content}).get_json()
            lat.append((time.perf_counter() - t0) * 1000)
            ok = neutralized(r, cfg) if malicious else (r["decision"] in ("ALLOW", "SANITIZE") and r["decision"] == "ALLOW")
            rows.append((group, name, r["decision"], r["verdict"]["label"], r["verdict"]["score"], ok))

    summary = {}
    for g in dict.fromkeys(r[0] for r in rows):
        sub = [r for r in rows if r[0] == g]
        summary[g] = {"total": len(sub), "ok": sum(1 for r in sub if r[5])}
    tp = sum(1 for r in rows if "вредонос" in r[0] and r[5])
    fn = sum(1 for r in rows if ("вредонос" in r[0] or "обход" in r[0]) and not r[5])
    # «обход сигнатур» считаем отдельно, в общую оценку recall они не входят
    mal = [r for r in rows if "вредонос" in r[0]]
    ben = [r for r in rows if "безопас" in r[0]]
    evs = [r for r in rows if "обход" in r[0]]
    res = {
        "malicious_total": len(mal), "malicious_neutralized": sum(1 for r in mal if r[5]),
        "benign_total": len(ben), "benign_allowed_unchanged": sum(1 for r in ben if r[5]),
        "evasion_total": len(evs), "evasion_neutralized": sum(1 for r in evs if r[5]),
        "latency_ms_mean": round(statistics.mean(lat), 2), "latency_ms_median": round(statistics.median(lat), 2),
        "latency_ms_p95": round(sorted(lat)[int(len(lat) * 0.95) - 1], 2), "latency_ms_max": round(max(lat), 2),
        "details": [dict(group=r[0], name=r[1], decision=r[2], label=r[3], score=r[4], ok=r[5]) for r in rows],
        "summary": summary,
    }
    res["recall"] = round(res["malicious_neutralized"] / res["malicious_total"], 3)
    res["false_positive_rate"] = round(1 - res["benign_allowed_unchanged"] / res["benign_total"], 3)
    os.makedirs("results", exist_ok=True)
    json.dump(res, open("results/evaluation.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"{'Группа':28}{'Образец':32}{'Решение':10}{'Вердикт':12}{'Балл':5}  OK")
    for r in rows:
        print(f"{r[0]:28}{r[1]:32}{r[2]:10}{r[3]:12}{r[4]:<5}  {'да' if r[5] else 'НЕТ'}")
    print()
    for g, v in summary.items():
        print(f"{g}: {v['ok']}/{v['total']}")
    print(f"Полнота (recall) на вредоносных: {res['recall']}  ·  Доля ложных срабатываний: {res['false_positive_rate']}")
    print(f"Задержка конвейера, мс: среднее {res['latency_ms_mean']}, медиана {res['latency_ms_median']}, p95 {res['latency_ms_p95']}")


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    main()
