"""Журнал событий безопасности (SQLite) и формирование оповещений."""
import json
import sqlite3
import threading
import time
from typing import Dict, List


class EventStore:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, item_id TEXT, kind TEXT, source TEXT, ctype TEXT,
            sha256 TEXT, filename TEXT, label TEXT, score INTEGER, decision TEXT, findings TEXT, actions TEXT)""")
        self.conn.commit()

    def add(self, ev: Dict) -> int:
        v = ev.get("verdict", {})
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO events(ts,item_id,kind,source,ctype,sha256,filename,label,score,decision,findings,actions) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), ev.get("item_id"), ev.get("kind"), ev.get("source"), ev.get("ctype"), ev.get("sha256"),
                 ev.get("filename"), v.get("label"), v.get("score"), ev.get("decision"),
                 json.dumps([f["id"] for f in ev.get("findings", [])], ensure_ascii=False),
                 json.dumps(ev.get("actions", []), ensure_ascii=False)))
            self.conn.commit()
            return cur.lastrowid

    def last(self, n: int = 50) -> List[Dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["findings"] = json.loads(d["findings"] or "[]")
            d["actions"] = json.loads(d["actions"] or "[]")
            out.append(d)
        return out

    def counts(self) -> Dict[str, int]:
        with self._lock:
            rows = self.conn.execute("SELECT decision, COUNT(*) c FROM events GROUP BY decision").fetchall()
        return {r["decision"]: r["c"] for r in rows}


def format_alert(ev: Dict) -> str:
    v = ev.get("verdict", {})
    icon = {"BLOCK": "ЗАБЛОКИРОВАНО", "SANITIZE": "ОЧИЩЕНО", "ALLOW": "РАЗРЕШЕНО"}.get(ev.get("decision"), "?")
    ids = ", ".join(f["id"] for f in ev.get("findings", [])) or "—"
    acts = ", ".join(ev.get("actions", [])) or "—"
    return (f"[{icon}] {ev.get('kind', '?').upper()} из {ev.get('source') or ev.get('filename') or 'неизвестного источника'}\n"
            f"Тип: {ev.get('ctype')} · вердикт: {v.get('label')} (балл {v.get('score')}, уверенность {v.get('confidence')})\n"
            f"Признаки: {ids}\nДействия: {acts}\nSHA-256: {(ev.get('sha256') or '')[:16]}…")
