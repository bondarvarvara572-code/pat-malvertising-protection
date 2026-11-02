"""Минимальная реализация метрик в формате Prometheus (без внешних зависимостей)."""
import threading
import time


def _fmt_labels(labels: dict) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


class Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = {}   # (name, labels_tuple) -> value
        self._gauges = {}
        self._hists = {}      # name -> {"buckets": [...], "data": {labels_tuple: [counts, sum, n]}}
        self._help = {}

    def describe(self, name: str, text: str):
        self._help[name] = text

    def inc(self, name: str, amount: float = 1.0, **labels):
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + amount

    def set(self, name: str, value: float, **labels):
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(self, name: str, value: float, buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0), **labels):
        with self._lock:
            h = self._hists.setdefault(name, {"buckets": list(buckets), "data": {}})
            lk = tuple(sorted(labels.items()))
            rec = h["data"].setdefault(lk, [[0] * len(h["buckets"]), 0.0, 0])
            for i, b in enumerate(h["buckets"]):
                if value <= b:
                    rec[0][i] += 1
            rec[1] += value
            rec[2] += 1

    def value(self, name: str, **labels) -> float:
        key = (name, tuple(sorted(labels.items())))
        return self._counters.get(key, self._gauges.get(key, 0.0))

    def render(self) -> str:
        out = []
        with self._lock:
            names = sorted({k[0] for k in self._counters})
            for n in names:
                out.append(f"# HELP {n} {self._help.get(n, n)}")
                out.append(f"# TYPE {n} counter")
                for (name, lk), v in sorted(self._counters.items()):
                    if name == n:
                        out.append(f"{n}{_fmt_labels(dict(lk))} {v}")
            names = sorted({k[0] for k in self._gauges})
            for n in names:
                out.append(f"# HELP {n} {self._help.get(n, n)}")
                out.append(f"# TYPE {n} gauge")
                for (name, lk), v in sorted(self._gauges.items()):
                    if name == n:
                        out.append(f"{n}{_fmt_labels(dict(lk))} {v}")
            for n, h in sorted(self._hists.items()):
                out.append(f"# HELP {n} {self._help.get(n, n)}")
                out.append(f"# TYPE {n} histogram")
                for lk, (counts, s, cnt) in h["data"].items():
                    base = dict(lk)
                    for b, c in zip(h["buckets"], counts):
                        out.append(f"{n}_bucket{_fmt_labels({**base, 'le': b})} {c}")
                    out.append(f"{n}_bucket{_fmt_labels({**base, 'le': '+Inf'})} {cnt}")
                    out.append(f"{n}_sum{_fmt_labels(base)} {s}")
                    out.append(f"{n}_count{_fmt_labels(base)} {cnt}")
        return "\n".join(out) + "\n"


class Timer:
    """Контекстный менеджер для измерения времени и записи в гистограмму."""
    def __init__(self, registry: Registry, name: str, **labels):
        self.r, self.name, self.labels = registry, name, labels

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.perf_counter() - self.t0
        self.r.observe(self.name, self.elapsed, **self.labels)
