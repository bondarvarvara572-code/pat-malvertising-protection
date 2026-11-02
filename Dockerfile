FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY services ./services
COPY lab ./lab
COPY config ./config
RUN useradd -u 10001 -m app && mkdir -p /data && chown -R app /app /data
USER 10001
# модуль запускаемого сервиса задаётся командой в docker-compose.yml / манифестах Kubernetes
CMD ["python", "-m", "services.content_collector.app"]
