#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

check() {
  local name="$1" cmd="$2"
  if eval "$cmd" > /dev/null 2>&1; then
    echo "  ✅ $name"
    PASS=$((PASS+1))
  else
    echo "  ❌ $name"
    FAIL=$((FAIL+1))
  fi
}

echo "═══════════════════════════════════════"
echo "  F040 Automated Gate"
echo "═══════════════════════════════════════"

echo ""
echo "── File Structure ──"
check "provider.py exists" "test -f norviq/telemetry/provider.py"
check "metrics.py exists" "test -f norviq/telemetry/metrics.py"
check "spans.py exists" "test -f norviq/telemetry/spans.py"
check "middleware.py exists" "test -f norviq/telemetry/middleware.py"
check "__init__.py exists" "test -f norviq/telemetry/__init__.py"

echo ""
echo "── Metrics Definitions ──"
check "tool_calls_total counter" "grep -q 'tool_call.*total\|tool_calls_total' norviq/telemetry/metrics.py"
check "tool_calls_blocked counter" "grep -q 'blocked.*total\|blocked_total' norviq/telemetry/metrics.py"
check "evaluation_latency histogram" "grep -q 'evaluation_latency\|latency.*histogram\|latency_ms' norviq/telemetry/metrics.py"
check "trust_score histogram" "grep -q 'trust_score\|trust.*distribution' norviq/telemetry/metrics.py"
check "cache_hits counter" "grep -q 'cache_hit' norviq/telemetry/metrics.py"
check "cache_misses counter" "grep -q 'cache_miss' norviq/telemetry/metrics.py"
check "active_agents gauge" "grep -q 'active_agent' norviq/telemetry/metrics.py"

echo ""
echo "── Spans ──"
check "create_tool_call_span function" "grep -q 'def create_tool_call_span\|tool_call_span' norviq/telemetry/spans.py"
check "enrich_span function" "grep -q 'def enrich_span' norviq/telemetry/spans.py"
check "Span attributes include decision" "grep -q 'decision' norviq/telemetry/spans.py"
check "Span attributes include trust_score" "grep -q 'trust_score' norviq/telemetry/spans.py"
check "Span attributes include tool_name" "grep -q 'tool_name' norviq/telemetry/spans.py"
check "Chain span for delegation" "grep -q 'chain\|delegation\|parent' norviq/telemetry/spans.py"

echo ""
echo "── Provider Setup ──"
check "setup_telemetry function" "grep -q 'def setup_telemetry' norviq/telemetry/provider.py"
check "MeterProvider setup" "grep -q 'MeterProvider' norviq/telemetry/provider.py"
check "TracerProvider setup" "grep -q 'TracerProvider' norviq/telemetry/provider.py"
check "Prometheus exporter" "grep -q 'prometheus\|Prometheus\|PrometheusMetricReader' norviq/telemetry/provider.py"
check "OTel collector exporter" "grep -q 'OTLP\|otlp\|OTLPSpanExporter' norviq/telemetry/provider.py"
check "shutdown_telemetry function" "grep -q 'def shutdown_telemetry\|shutdown' norviq/telemetry/provider.py"

echo ""
echo "── FastAPI Middleware ──"
check "TelemetryMiddleware class" "grep -q 'class TelemetryMiddleware\|TelemetryMiddleware' norviq/telemetry/middleware.py"
check "Records request latency" "grep -q 'latency\|perf_counter\|time' norviq/telemetry/middleware.py"
check "Creates span per request" "grep -q 'start_span\|start_as_current_span\|tracer' norviq/telemetry/middleware.py"

echo ""
echo "── Prometheus Endpoint ──"
check "Metrics endpoint in API" "grep -q 'metrics\|prometheus\|make_asgi_app' norviq/api/main.py"

echo ""
echo "── Evaluator Integration ──"
check "Metrics recorded in evaluator" "grep -q 'tool_call_total\|telemetry\|metric' norviq/engine/evaluator.py"
check "Span created in evaluator" "grep -q 'span\|create_tool_call_span\|tracer' norviq/engine/evaluator.py"

echo ""
echo "── Cache Integration ──"
check "Cache hit metric" "grep -q 'cache_hit\|cache_hits' norviq/engine/cache.py"
check "Cache miss metric" "grep -q 'cache_miss\|cache_misses' norviq/engine/cache.py"

echo ""
echo "── Config ──"
check "otel_endpoint in config" "grep -q 'otel_endpoint\|NRVQ_OTEL_ENDPOINT' norviq/config.py"
check "otel_enabled in config" "grep -q 'otel_enabled\|NRVQ_OTEL_ENABLED' norviq/config.py"

echo ""
echo "── Grafana Dashboard ──"
check "Dashboard JSON exists" "test -f docs/grafana-dashboard.json || test -f helm/norviq/templates/grafana-dashboard-configmap.yaml"

echo ""
echo "── Error Codes ──"
check "NRVQ-TEL-12000 present" "grep -rq 'NRVQ-TEL-12000' norviq/telemetry/"
check "NRVQ-TEL-12001 present" "grep -rq 'NRVQ-TEL-12001' norviq/telemetry/"

echo ""
echo "── Tests ──"
check "test_metrics.py exists" "test -f tests/telemetry/test_metrics.py"
check "test_spans.py exists" "test -f tests/telemetry/test_spans.py"
check "test_provider.py exists" "test -f tests/telemetry/test_provider.py"

echo ""
echo "── Architecture ──"
check "class.mmd exists" "test -f architecture/F040.class.mmd"
check "sequence.mmd exists" "test -f architecture/F040.sequence.mmd"
check "deps.mmd exists" "test -f architecture/F040.deps.mmd"
check "registry exists" "test -f registry/F040.md"

echo ""
echo "── No Stale Code ──"
check "No print() in telemetry" "! grep -rq 'print(' norviq/telemetry/"
check "SPDX headers" "head -1 norviq/telemetry/provider.py | grep -q 'SPDX'"

echo ""
echo "── Regression check ──"
check "history file exists" "test -f tests/.history/F040.md"
check "no @pytest.mark.xfail without reason" "! grep -rn 'pytest.mark.xfail(' tests/.history/ 2>/dev/null | grep -v reason"

echo ""
echo "═══════════════════════════════════════"
echo "  Result: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
  echo "  🟢 GATE PASSED — safe to commit"
  exit 0
else
  echo "  🔴 GATE FAILED — fix $FAIL items"
  exit 1
fi
