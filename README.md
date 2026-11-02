# PAT: паттерн защиты от внедрения вредоносного кода через рекламу, сервисы и контент

Состав: `services/` – четыре микросервиса паттерна; `lab/` – лабораторный стенд (рекламная сеть, сервер атакующего, веб-приложение);
`tests/` – автотесты и тестовый корпус; `scripts/` – генератор нагрузки и оценка корпуса; `k8s/` – манифесты Kubernetes;
`monitoring/` – Prometheus и Grafana; `samples/` – примеры запросов; `docs/` – схемы.

Быстрый старт:

    python -m venv venv && venv\Scripts\activate   (Linux/macOS: source venv/bin/activate)
    pip install -r requirements.txt
    python -m tests.run_all
    python scripts/evaluate_corpus.py
    docker compose up -d --build

Подробности – в файле «Руководство по проведению экспериментов».
