$ns = "pat-ns"
$pairs = @(
  "webapp-vulnerable 8080:8080",
  "webapp-protected 8081:8080",
  "attacker-server 9999:9999",
  "content-collector 8001:8001",
  "visual-alert 8004:8004",
  "grafana 3000:3000",
  "prometheus 9090:9090"
)
foreach ($p in $pairs) {
  $parts = $p.Split(" ")
  $svc = "svc/" + $parts[0]
  Start-Process -FilePath "kubectl" -ArgumentList @("-n", $ns, "port-forward", $svc, $parts[1]) -WindowStyle Minimized
  Write-Host ("started: " + $svc + " -> localhost:" + $parts[1].Split(":")[0])
}
Write-Host "Done. Check: Get-Process kubectl"
