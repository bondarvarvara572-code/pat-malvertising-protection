#!/usr/bin/env bash
# Проброс портов сервисов из Kubernetes на localhost (Linux/macOS). Остановка: Ctrl+C
NS=pat-ns
kubectl -n $NS port-forward svc/webapp-vulnerable 8080:8080 &
kubectl -n $NS port-forward svc/webapp-protected 8081:8080 &
kubectl -n $NS port-forward svc/attacker-server 9999:9999 &
kubectl -n $NS port-forward svc/content-collector 8001:8001 &
kubectl -n $NS port-forward svc/visual-alert 8004:8004 &
kubectl -n $NS port-forward svc/grafana 3000:3000 &
kubectl -n $NS port-forward svc/prometheus 9090:9090 &
trap 'kill $(jobs -p)' INT TERM
wait
