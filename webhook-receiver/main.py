# In-memory demo store — not persistent across restarts.
# For production alternatives (Redis Streams, time-series DB), see README.md §7.

from collections import deque
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
import asyncio
import datetime
import json
import pathlib
import ssl
import urllib.parse
import urllib.request as _urlreq
import uuid

app = FastAPI()

raw_alerts: deque = deque(maxlen=100)
alert_buffer: deque = deque(maxlen=100)
triage_reports: deque = deque(maxlen=100)
_sse_queues: list[asyncio.Queue] = []
_agent_busy: bool = False  # prevents overlapping triage cycles

_AGENT_A2A_URL = (
    "http://kagent-controller.kagent.svc.cluster.local:8083"
    "/api/a2a/kagent/triage-agent"
)

# Namespaces where false-positive system alerts originate — excluded from both
# the triage buffer AND the raw alerts UI so the demo stays focused on prod.
_EXCLUDED_NAMESPACES = {
    "kagent", "falco", "falco-operator", "kube-system",
    "monitoring", "agentgateway-system", "demo",
}

_PROM_BASE = (
    "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"
)
_K8S_API = "https://kubernetes.default.svc"
_SA_TOKEN = pathlib.Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_SA_CA = pathlib.Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


async def _broadcast(event: str, data: str) -> None:
    for q in list(_sse_queues):
        await q.put((event, data))


# ─── Falcosidekick endpoints ───────────────────────────────────────────────────

@app.post("/raw")
async def receive_raw(request: Request):
    body = await request.json()
    body["timestamp_received"] = _now()
    raw_alerts.appendleft(body)
    await _broadcast("alert", json.dumps(body))
    return {"status": "ok"}


@app.post("/ingest")
async def ingest(request: Request):
    body = await request.json()
    body["timestamp_received"] = _now()
    ns = (body.get("output_fields") or {}).get("k8s.ns.name", "")
    # Filter system namespaces from both the UI and the triage buffer so the
    # demo only shows user-workload alerts (kagent-postgresql etc. are noise).
    if ns in _EXCLUDED_NAMESPACES:
        return {"status": "ok"}
    raw_alerts.appendleft(body)
    await _broadcast("alert", json.dumps(body))
    alert_buffer.append(body)
    return {"status": "ok"}


@app.get("/buffer")
async def get_buffer():
    return JSONResponse(list(alert_buffer))


@app.get("/history")
async def history():
    """Returns current raw_alerts and triage_reports for UI initial load."""
    return JSONResponse({
        "raw_alerts": list(raw_alerts),
        "triage_reports": list(triage_reports),
        "buffer_count": len(alert_buffer),
    })


@app.post("/result")
async def post_result(request: Request):
    body = await request.json()
    triage_reports.appendleft(body)
    alert_buffer.clear()
    await _broadcast("report", json.dumps(body))
    return {"status": "ok"}


# ─── SSE stream ───────────────────────────────────────────────────────────────

@app.get("/events")
async def sse_stream(request: Request):
    q: asyncio.Queue = asyncio.Queue()
    _sse_queues.append(q)

    async def stream():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(q.get(), timeout=5.0)
                    yield f"event: {event}\ndata: {data}\n\n"
                except asyncio.TimeoutError:
                    yield "data: ping\n\n"
        finally:
            if q in _sse_queues:
                _sse_queues.remove(q)

    return StreamingResponse(stream(), media_type="text/event-stream")


# ─── Prometheus helper ────────────────────────────────────────────────────────

def _prom_range_max_sync(query: str, lookback_minutes: int = 10) -> float | None:
    """Runs a PromQL range query over the last N minutes; returns max value or None."""
    now = datetime.datetime.utcnow().timestamp()
    start = now - lookback_minutes * 60
    url = (
        f"{_PROM_BASE}/api/v1/query_range"
        f"?query={urllib.parse.quote(query)}"
        f"&start={start:.0f}&end={now:.0f}&step=15"
    )
    try:
        with _urlreq.urlopen(_urlreq.Request(url), timeout=5) as r:
            data = json.loads(r.read())
        values = [
            float(v[1])
            for series in data.get("data", {}).get("result", [])
            for v in series.get("values", [])
            if v[1] not in ("NaN", "+Inf", "-Inf")
        ]
        return max(values) if values else None
    except Exception:
        return None


def _get_pod_metrics_sync(pod: str, namespace: str) -> dict:
    cpu_peak = _prom_range_max_sync(
        f'rate(container_cpu_usage_seconds_total{{pod="{pod}",namespace="{namespace}",container!=""}}[30s])'
    )
    mem_peak = _prom_range_max_sync(
        f'container_memory_working_set_bytes{{pod="{pod}",namespace="{namespace}",container!=""}}'
    )
    net_peak = _prom_range_max_sync(
        f'rate(container_network_transmit_bytes_total{{pod="{pod}"}}[30s])'
    )

    def _fmt_bytes(b: float | None) -> str:
        if b is None:
            return "no data"
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    return {
        "pod": pod,
        "namespace": namespace,
        "query_window": "last 10 minutes",
        "cpu_peak_cores": round(cpu_peak, 6) if cpu_peak is not None else None,
        "memory_peak": _fmt_bytes(mem_peak),
        "network_tx_peak": _fmt_bytes(net_peak) + "/s" if net_peak is not None else "no data",
        "note": (
            "No metrics found — pod may have exited before Prometheus scraped it"
            if cpu_peak is None and mem_peak is None
            else "Metrics captured from Prometheus cadvisor scrapes"
        ),
    }


# ─── K8s Events helper ────────────────────────────────────────────────────────

def _get_pod_events_sync(pod: str, namespace: str) -> dict:
    """Fetches K8s Events for a pod via the in-cluster API using the mounted SA token."""
    try:
        token = _SA_TOKEN.read_text()
        ssl_ctx = ssl.create_default_context(cafile=str(_SA_CA))
        qs = (
            f"fieldSelector=involvedObject.name%3D{urllib.parse.quote(pod)}"
            f"&limit=5"
        )
        url = f"{_K8S_API}/api/v1/namespaces/{urllib.parse.quote(namespace)}/events?{qs}"
        req = _urlreq.Request(url, headers={"Authorization": f"Bearer {token}"})
        with _urlreq.urlopen(req, context=ssl_ctx, timeout=5) as r:
            data = json.loads(r.read())
        events = [
            {
                "type": e.get("type", ""),
                "reason": e.get("reason", ""),
                "message": (e.get("message") or "")[:120],
                "count": e.get("count", 1),
            }
            for e in data.get("items", [])
        ]
        return {
            "pod": pod,
            "namespace": namespace,
            "event_count": len(events),
            "events": events,
        }
    except Exception as e:
        return {"error": str(e), "pod": pod, "namespace": namespace, "events": []}


# ─── MCP STREAMABLE_HTTP endpoint ─────────────────────────────────────────────
def _normalize_report(raw: dict, current_buffer: list) -> dict:
    """Normalize post_triage_result arguments and enforce hard business rules.

    Two responsibilities:
    1. Map every field name variant the model uses to the canonical schema.
    2. Override severity/decision based on the actual alert buffer — the model
       sometimes ignores tool-description rules (especially Coder models).
    """
    def _str(v, default=""):
        return str(v) if v is not None else default

    def _int(v, default=0):
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    def _list(v):
        if isinstance(v, list):
            return v
        return []

    # Extract workloads from the model's output, handling all observed field names.
    raw_wl = _list(raw.get("affected_workloads"))
    workloads = []
    for w in raw_wl:
        if not isinstance(w, dict):
            continue
        if "affected_workloads_list" in w and not w.get("pod") and not w.get("name"):
            inner = w.get("affected_workloads_list", [])
            if inner and isinstance(inner, list) and isinstance(inner[0], dict):
                w = {**w, **inner[0]}
        pod = (w.get("pod") or w.get("k8s_pod_name") or w.get("name") or
               w.get("pod_name") or w.get("k8s.pod.name") or "")
        ns = (w.get("namespace") or w.get("k8s_ns_name") or
              w.get("namespace_name") or w.get("k8s.ns.name") or "")
        image = (w.get("image") or w.get("image_repository") or
                 w.get("container_image_repository") or "")
        timeline = w.get("alert_timeline")
        if isinstance(timeline, dict):
            timeline = (timeline.get("alerts") or timeline.get("events") or
                        timeline.get("alert_timeline") or [])
        if pod:
            workloads.append({
                "pod": pod, "namespace": ns, "image": image,
                "alert_timeline": _list(timeline),
            })

    # Fallback: if the model returned no workloads, reconstruct from the buffer.
    if not workloads and current_buffer:
        seen_pods: dict = {}
        for a in current_buffer:
            of = a.get("output_fields") or {}
            pod = of.get("k8s.pod.name") or of.get("k8s_pod_name") or ""
            ns = of.get("k8s.ns.name") or of.get("k8s_ns_name") or ""
            image = (of.get("container.image.repository") or
                     of.get("container_image_repository") or "")
            if pod and pod not in seen_pods:
                seen_pods[pod] = {"pod": pod, "namespace": ns, "image": image,
                                  "alert_timeline": []}
            if pod:
                ts = a.get("time") or a.get("timestamp_received", "")
                rule = a.get("rule", "")
                pri = a.get("priority", "")
                seen_pods[pod]["alert_timeline"].append(f"{ts} {rule} ({pri})")
        workloads = list(seen_pods.values())

    # Derive ground-truth priority facts from the actual buffer — do not trust the model.
    buf_priorities = {(a.get("priority") or "").upper() for a in current_buffer}
    buf_rules = {a.get("rule", "") for a in current_buffer}
    buf_pods: set = set()
    for a in current_buffer:
        of = a.get("output_fields") or {}
        p = of.get("k8s.pod.name") or of.get("k8s_pod_name") or ""
        if p:
            buf_pods.add(p)

    # Count distinct rule types per pod (multi-step pattern detection).
    rules_per_pod: dict = {}
    for a in current_buffer:
        of = a.get("output_fields") or {}
        pod = of.get("k8s.pod.name") or of.get("k8s_pod_name") or ""
        rules_per_pod.setdefault(pod, set()).add(a.get("rule", ""))
    max_rules_on_one_pod = max((len(v) for v in rules_per_pod.values()), default=0)

    model_severity = _str(raw.get("severity"), "MEDIUM").upper()
    model_decision = _str(raw.get("decision"), "ESCALATE").upper()
    model_confidence = _int(raw.get("confidence"), 50)

    # Hard override rules — these cannot be suppressed by the model's output.
    _SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    floor_severity = model_severity
    if "CRITICAL" in buf_priorities:
        floor_severity = "CRITICAL"
    elif "ERROR" in buf_priorities or max_rules_on_one_pod >= 3:
        floor_severity = max(floor_severity, "HIGH", key=lambda s: _SEVERITY_RANK.get(s, 0))
    elif max_rules_on_one_pod >= 2:
        floor_severity = max(floor_severity, "HIGH", key=lambda s: _SEVERITY_RANK.get(s, 0))

    # Decision must be ESCALATE if: confidence < 70, or any ERROR/CRITICAL alert,
    # or severity ended up HIGH or above.
    must_escalate = (
        model_confidence < 70
        or "CRITICAL" in buf_priorities
        or "ERROR" in buf_priorities
        or _SEVERITY_RANK.get(floor_severity, 0) >= _SEVERITY_RANK["HIGH"]
    )
    final_decision = "ESCALATE" if must_escalate else model_decision

    report = {
        "window_start": _str(raw.get("window_start")),
        "window_end": _str(raw.get("window_end")),
        "alert_count": _int(raw.get("alert_count")) or len(current_buffer),
        "affected_workloads": workloads,
        "correlation_summary": _str(raw.get("correlation_summary")),
        "severity": floor_severity,
        "confidence": model_confidence,
        "evidence": _list(raw.get("evidence")),
        "prometheus_anomalies": _list(raw.get("prometheus_anomalies")),
        "recommended_action": _str(raw.get("recommended_action")),
        "decision": final_decision,
        "suppression_reason": raw.get("suppression_reason") if final_decision == "SUPPRESS" else None,
        "timestamp_received": _now(),
    }
    return report


# Exposes get_alert_buffer, get_pod_metrics, and post_triage_result as MCP tools
# so kagent's triage-agent can read the alert window, query Prometheus, and post
# results — all without requiring external HTTP tool CRDs.

_MCP_TOOLS = [
    {
        "name": "get_alert_buffer",
        "description": (
            "Returns the current batch of Falco security alerts accumulated since "
            "the last triage cycle. Returns a JSON array. Call this first."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_pod_events",
        "description": (
            "Fetches Kubernetes Events for a specific pod (CrashLoopBackOff, OOMKill, "
            "restarts, scheduling failures, image pull errors). "
            "Call this after k8s_get_resources for lifecycle context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pod": {"type": "string", "description": "Pod name"},
                "namespace": {"type": "string", "description": "Namespace"},
            },
            "required": ["pod", "namespace"],
        },
    },
    {
        "name": "get_pod_metrics",
        "description": (
            "Queries in-cluster Prometheus for CPU, memory, and network metrics "
            "of a specific pod over the last 10 minutes. "
            "Call this after get_pod_events to detect resource anomalies."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pod": {"type": "string", "description": "Pod name"},
                "namespace": {"type": "string", "description": "Namespace"},
            },
            "required": ["pod", "namespace"],
        },
    },
    {
        "name": "post_triage_result",
        "description": (
            "Submits the completed triage report. Must be called as a tool — never written as text. "
            "Calling this tool flushes the alert buffer.\n\n"

            "SEVERITY rules: "
            "CRITICAL if 3+ different rule types on the same pod in one window, or any CRITICAL-priority alert. "
            "HIGH if any ERROR-priority alert or 2+ different rule types on the same pod. "
            "MEDIUM if a single WARNING. LOW only for noise or expected activity.\n\n"

            "DECISION rules: "
            "ESCALATE if confidence<70, if severity>=HIGH, or if any alert has ERROR/CRITICAL priority. "
            "SUPPRESS only if confidence>=90 AND severity is LOW or MEDIUM AND no ERROR/CRITICAL alerts.\n\n"

            "correlation_summary: Two paragraphs (see system prompt for format). No bullet points.\n\n"

            "recommended_action: 3-5 numbered investigation steps naming the exact pod, files, and kubectl commands. "
            "Do NOT recommend pod deletion, network policy changes, secret rotation, or RBAC changes — "
            "those are remediation actions for the IR team after human review.\n\n"
            "evidence: One sentence per alert, per K8s event finding, and per Prometheus anomaly."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "window_start": {"type": "string"},
                "window_end": {"type": "string"},
                "alert_count": {"type": "integer"},
                "affected_workloads": {"type": "array", "items": {"type": "object"}},
                "correlation_summary": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "prometheus_anomalies": {"type": "array", "items": {"type": "string"}},
                "recommended_action": {"type": "string"},
                "decision": {"type": "string", "enum": ["ESCALATE", "SUPPRESS"]},
                "suppression_reason": {"type": ["string", "null"]},
            },
            "required": [
                "window_start", "window_end", "alert_count", "severity",
                "confidence", "decision", "correlation_summary", "recommended_action",
            ],
        },
    },
]


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """MCP STREAMABLE_HTTP server for triage tools (alert buffer + result posting)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=200,
        )

    method = body.get("method", "")
    rpc_id = body.get("id")

    if method == "initialize":
        result = {
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "webhook-receiver", "version": "1.0.0"},
            "capabilities": {"tools": {}},
        }
    elif method in ("notifications/initialized", "notifications/cancelled"):
        return JSONResponse({}, status_code=200)
    elif method == "tools/list":
        result = {"tools": _MCP_TOOLS}
    elif method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        # Gemma4/ADK sometimes serializes arguments as a JSON string (OpenAI format).
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}

        if tool_name == "get_alert_buffer":
            # Return a minimal projection per alert to keep LLM context small.
            raw = list(alert_buffer)
            seen: dict = {}
            summary = []
            for a in raw:
                of = a.get("output_fields") or {}
                pod = of.get("k8s.pod.name") or of.get("k8s_pod_name") or ""
                ns = of.get("k8s.ns.name") or of.get("k8s_ns_name") or ""
                image = (of.get("container.image.repository") or
                         of.get("container_image_repository") or "")
                key = (a.get("rule", ""), pod)
                if key not in seen:
                    seen[key] = 0
                    summary.append({
                        "rule": a.get("rule", ""),
                        "priority": a.get("priority", ""),
                        "time": a.get("time") or a.get("timestamp_received", ""),
                        "pod": pod,
                        "namespace": ns,
                        "image": image,
                        "output": (a.get("output") or "")[:120],
                    })
                seen[key] += 1
            for s in summary:
                s["repeat_count"] = seen[(s["rule"], s["pod"])]
            result = {"content": [{"type": "text", "text": json.dumps(summary[:15])}]}
        elif tool_name == "get_pod_events":
            pod = arguments.get("pod", "")
            namespace = arguments.get("namespace", "prod")
            events = await asyncio.to_thread(_get_pod_events_sync, pod, namespace)
            result = {"content": [{"type": "text", "text": json.dumps(events)}]}
        elif tool_name == "get_pod_metrics":
            pod = arguments.get("pod", "")
            namespace = arguments.get("namespace", "prod")
            metrics = await asyncio.to_thread(_get_pod_metrics_sync, pod, namespace)
            result = {"content": [{"type": "text", "text": json.dumps(metrics)}]}
        elif tool_name == "post_triage_result":
            report = _normalize_report(arguments, list(alert_buffer))
            triage_reports.appendleft(report)
            alert_buffer.clear()
            await _broadcast("report", json.dumps(report))
            result = {"content": [{"type": "text", "text": '{"status":"ok","flushed":true}'}]}
        else:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                },
                status_code=200,
            )
    else:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"},
            },
            status_code=200,
        )

    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


# ─── 30-second triage trigger ─────────────────────────────────────────────────


def _invoke_agent_sync() -> None:
    """Blocking HTTP call to kagent A2A endpoint — runs in a thread pool."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            # New sessionId each trigger so kagent starts a fresh conversation.
            # Without this, kagent appends to the same session and the accumulated
            # conversation history grows until the model loses its tool-calling behaviour.
            "sessionId": str(uuid.uuid4()),
            "message": {
                "messageId": str(uuid.uuid4()),
                "role": "user",
                "parts": [{"kind": "text", "text": "Run triage cycle now."}],
            },
        },
    }).encode()
    req = _urlreq.Request(
        _AGENT_A2A_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with _urlreq.urlopen(req, timeout=180) as resp:
            resp.read()
    except Exception:
        pass  # silently ignore — agent may not be ready yet


async def _triage_trigger_loop() -> None:
    """Polls alert_buffer every 30 s; triggers kagent triage-agent when alerts are buffered.
    After triggering, waits 120 s before the next trigger to avoid overwhelming the local LLM.
    """
    global _agent_busy
    await asyncio.sleep(60)  # initial delay to let kagent finish starting up
    while True:
        await asyncio.sleep(30)
        if alert_buffer and not _agent_busy:
            _agent_busy = True
            try:
                await asyncio.to_thread(_invoke_agent_sync)
            finally:
                _agent_busy = False
            # Post-trigger cooldown: give the LLM time to complete before re-triggering.
            await asyncio.sleep(120)


@app.on_event("startup")
async def _startup() -> None:
    asyncio.create_task(_triage_trigger_loop())


# ─── UI ───────────────────────────────────────────────────────────────────────

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Falco Agentic Triage</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; font-size: 14px; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
  header h1 { font-size: 16px; color: #58a6ff; letter-spacing: 0.5px; }
  .status-bar { display: flex; gap: 16px; font-size: 12px; color: #8b949e; margin-left: auto; align-items: center; flex-wrap: wrap; }
  .status-bar strong { color: #c9d1d9; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #3fb950; margin-right: 4px; }
  .dot.warn { background: #d29922; }
  .dot.err { background: #f85149; }
  nav { background: #161b22; border-bottom: 1px solid #30363d; display: flex; padding: 0 8px; }
  nav button { background: none; border: none; color: #8b949e; padding: 10px 16px; cursor: pointer; font-size: 13px; font-family: inherit; border-bottom: 2px solid transparent; transition: color 0.15s; }
  nav button.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  nav button:hover { color: #c9d1d9; }
  .tab-content { display: none; padding: 16px; max-width: 1200px; margin: 0 auto; }
  .tab-content.active { display: block; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 12px; padding: 14px; }
  .card-header { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; white-space: nowrap; }
  .badge.critical  { background: #490202; color: #ff7b72; border: 1px solid #ff7b72; }
  .badge.error     { background: #3d1a00; color: #ffa657; border: 1px solid #ffa657; }
  .badge.warning   { background: #272115; color: #d29922; border: 1px solid #d29922; }
  .badge.notice, .badge.informational { background: #0c2d6b; color: #79c0ff; border: 1px solid #79c0ff; }
  .badge.debug     { background: #1f1f1f; color: #8b949e; border: 1px solid #484f58; }
  .badge.high      { background: #490202; color: #ff7b72; border: 1px solid #ff7b72; }
  .badge.medium    { background: #272115; color: #d29922; border: 1px solid #d29922; }
  .badge.low       { background: #0c2d6b; color: #79c0ff; border: 1px solid #79c0ff; }
  .badge.escalate  { background: #490202; color: #ff7b72; border: 1px solid #ff7b72; }
  .badge.suppress  { background: #1f1f1f; color: #8b949e; border: 1px solid #484f58; }
  .rule-name { color: #e6edf3; font-weight: bold; flex: 1; min-width: 0; word-break: break-word; }
  .timestamp { font-size: 11px; color: #6e7681; white-space: nowrap; }
  .meta { font-size: 12px; color: #8b949e; margin-bottom: 6px; }
  .output { margin-top: 8px; font-size: 12px; color: #8b949e; background: #0d1117; padding: 8px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }
  .report-section { margin-top: 10px; }
  .report-section h4 { font-size: 12px; color: #58a6ff; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
  .narrative { font-size: 13px; color: #c9d1d9; line-height: 1.6; }
  ul.evidence { list-style: none; padding: 0; }
  ul.evidence li { font-size: 12px; color: #8b949e; padding: 2px 0 2px 14px; position: relative; line-height: 1.5; }
  ul.evidence li::before { content: "›"; color: #d29922; position: absolute; left: 0; }
  .action { font-size: 13px; color: #3fb950; background: #0d1f14; padding: 10px 12px; border-radius: 4px; border-left: 3px solid #3fb950; margin-top: 10px; line-height: 1.5; }
  .suppression { font-size: 12px; color: #8b949e; margin-top: 6px; font-style: italic; }
  details { margin-top: 10px; }
  summary { cursor: pointer; color: #58a6ff; font-size: 12px; user-select: none; }
  summary:hover { color: #79c0ff; }
  pre { font-size: 11px; color: #8b949e; background: #0d1117; padding: 10px; border-radius: 4px; overflow-x: auto; margin-top: 6px; white-space: pre; line-height: 1.5; }
  .empty-state { color: #484f58; text-align: center; padding: 60px 20px; font-size: 15px; }
  .confidence-wrap { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #8b949e; }
  .confidence-bar { display: inline-block; background: #30363d; border-radius: 4px; height: 8px; width: 80px; overflow: hidden; }
  .confidence-fill { height: 100%; background: #3fb950; border-radius: 4px; }
  .confidence-fill.mid { background: #d29922; }
  .confidence-fill.low-conf { background: #f85149; }
  .workload-block { background: #0d1117; border-radius: 4px; padding: 8px 10px; margin-bottom: 6px; }
  .workload-name { font-size: 13px; color: #e6edf3; font-weight: bold; }
  .workload-image { font-size: 11px; color: #6e7681; margin-top: 4px; margin-bottom: 6px; }
  .timeline-item { font-size: 11px; color: #8b949e; padding: 1px 0; }
</style>
</head>
<body>
<header>
  <h1>Falco Agentic Triage</h1>
  <div class="status-bar">
    <span><span class="dot" id="conn-dot"></span><span id="conn-status">connecting…</span></span>
    <span>Buffer: <strong id="buffer-count">0</strong> alerts</span>
    <span>Last report: <strong id="last-report">—</strong></span>
  </div>
</header>
<nav>
  <button class="active" onclick="switchTab(event,'raw')">Raw Alerts (<span id="raw-count">0</span>)</button>
  <button onclick="switchTab(event,'reports')">Triage Reports (<span id="report-count">0</span>)</button>
</nav>
<div id="tab-raw" class="tab-content active">
  <div id="raw-container"><div class="empty-state">No alerts yet — run <code>make scenario-a</code> or <code>make scenario-b</code> to generate events.</div></div>
</div>
<div id="tab-reports" class="tab-content">
  <div id="reports-container"><div class="empty-state">No triage reports yet — the agent runs every 30 seconds when alerts are buffered.</div></div>
</div>

<script>
let rawCount = 0, reportCount = 0, bufferCount = 0;

function switchTab(e, name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  e.target.classList.add('active');
}

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmtAction(s) {
  if (!s) return '<span style="color:#6e7681"> —</span>';
  // Detect numbered list: "1. ... 2. ..." — split on the pattern and render as <ol>
  const items = s.split(/(?=\d+\.\s)/).map(p => p.replace(/^\d+\.\s*/, '').trim()).filter(Boolean);
  if (items.length > 1) {
    return '<ol style="margin:6px 0 0 18px;padding:0">' + items.map(i => `<li>${esc(i)}</li>`).join('') + '</ol>';
  }
  return ': ' + esc(s);
}
function badgeCls(v) { return (v||'debug').toLowerCase().replace(/[^a-z]/g,''); }

function renderRaw(d) {
  const pri = (d.priority || 'debug').toLowerCase();
  const ns  = d.output_fields?.['k8s.ns.name'] || d.output_fields?.['k8smeta.namespace.name'] || '—';
  const pod = d.output_fields?.['k8s.pod.name'] || d.output_fields?.['k8smeta.pod.name'] || '—';
  return `<div class="card">
    <div class="card-header">
      <span class="timestamp">${esc(d.timestamp_received)}</span>
      <span class="badge ${badgeCls(pri)}">${esc(pri)}</span>
      <span class="rule-name">${esc(d.rule)}</span>
    </div>
    <div class="meta">pod: <strong>${esc(pod)}</strong> &nbsp;|&nbsp; ns: <strong>${esc(ns)}</strong></div>
    <div class="output">${esc(d.output)}</div>
  </div>`;
}

function renderReport(d) {
  const sev  = (d.severity  || 'LOW').toLowerCase();
  const dec  = (d.decision  || '?').toLowerCase();
  const conf = d.confidence || 0;
  const fillCls = conf >= 70 ? '' : conf >= 40 ? 'mid' : 'low-conf';

  const wls = (d.affected_workloads || []).map(w => {
    const timelineHtml = (w.alert_timeline || []).map(t => {
      if (typeof t === 'string') return `<div class="timeline-item">› ${esc(t)}</div>`;
      const ts = t.time || t.timestamp || '';
      const typ = t.type || t.priority || '';
      return `<div class="timeline-item">› <span class="badge ${badgeCls(typ)}" style="font-size:9px;padding:1px 5px">${esc(typ)}</span> ${esc(ts)}</div>`;
    }).join('');
    const desc = w.alert_timeline_description || '';
    return `
    <div class="workload-block">
      <div class="workload-name">${esc(w.pod||w.k8s_pod_name||w.name)} <span style="color:#6e7681">/ ${esc(w.namespace||w.k8s_ns_name)}</span></div>
      <div class="workload-image">${esc(w.image||w.image_repository||w.container_image_repository)}</div>
      ${timelineHtml}
      ${desc ? `<div style="font-size:11px;color:#6e7681;margin-top:4px;font-style:italic">${esc(desc)}</div>` : ''}
    </div>`;
  }).join('');

  const evidence = (d.evidence || []).map(e => `<li>${esc(e)}</li>`).join('');
  const anomalies = (d.prometheus_anomalies || []).map(a => `<li>${esc(a)}</li>`).join('');

  return `<div class="card">
    <div class="card-header">
      <span class="timestamp">${esc(d.window_start)} → ${esc(d.window_end)}</span>
      <span class="badge ${badgeCls(sev)}">${esc(d.severity||'LOW')}</span>
      <span class="badge ${badgeCls(dec)}">${esc(d.decision||'?')}</span>
      <span class="confidence-wrap">
        ${conf}% confidence
        <span class="confidence-bar"><span class="confidence-fill ${fillCls}" style="width:${conf}%"></span></span>
      </span>
      <span style="font-size:12px;color:#6e7681">${d.alert_count||0} alerts</span>
    </div>
    ${wls ? `<div class="report-section"><h4>Affected Workloads</h4>${wls}</div>` : ''}
    <div class="report-section">
      <h4>Correlation Summary</h4>
      ${(d.correlation_summary||'').split(/\n+|(?=Paragraph \d+:)/i).filter(Boolean).map(p=>`<p class="narrative">${esc(p.replace(/^Paragraph \d+:\s*/i,'').trim())}</p>`).filter(p=>p!='<p class="narrative"></p>').join('')}
    </div>
    ${evidence ? `<div class="report-section"><h4>Evidence</h4><ul class="evidence">${evidence}</ul></div>` : ''}
    ${anomalies ? `<div class="report-section"><h4>Prometheus Anomalies</h4><ul class="evidence">${anomalies}</ul></div>` : ''}
    <div class="action"><strong>Recommended action</strong>${fmtAction(d.recommended_action)}</div>
    ${d.suppression_reason ? `<p class="suppression">Suppression reason: ${esc(d.suppression_reason)}</p>` : ''}
    <details><summary>Full JSON</summary><pre>${esc(JSON.stringify(d, null, 2))}</pre></details>
  </div>`;
}

// Load historical alerts and reports on page open
fetch('/history').then(r => r.json()).then(h => {
  document.getElementById('buffer-count').textContent = h.buffer_count || 0;
  (h.raw_alerts || []).slice().reverse().forEach(d => {
    rawCount++;
    const c = document.getElementById('raw-container');
    if (c.querySelector('.empty-state')) c.innerHTML = '';
    c.insertAdjacentHTML('beforeend', renderRaw(d));
  });
  document.getElementById('raw-count').textContent = rawCount;
  (h.triage_reports || []).slice().reverse().forEach(d => {
    reportCount++;
    document.getElementById('report-count').textContent = reportCount;
    const c = document.getElementById('reports-container');
    if (c.querySelector('.empty-state')) c.innerHTML = '';
    c.insertAdjacentHTML('beforeend', renderReport(d));
    document.getElementById('last-report').textContent = new Date().toLocaleTimeString();
  });
});

const es = new EventSource('/events');
es.onopen = () => {
  document.getElementById('conn-dot').className = 'dot';
  document.getElementById('conn-status').textContent = 'connected';
};
es.onerror = () => {
  document.getElementById('conn-dot').className = 'dot warn';
  document.getElementById('conn-status').textContent = 'reconnecting…';
};
es.addEventListener('alert', ev => {
  const d = JSON.parse(ev.data);
  rawCount++;
  document.getElementById('raw-count').textContent = rawCount;
  // Buffer count is tracked server-side; fetch the real count
  fetch('/history').then(r=>r.json()).then(h=>{
    document.getElementById('buffer-count').textContent = h.buffer_count || 0;
  });
  const c = document.getElementById('raw-container');
  if (c.querySelector('.empty-state')) c.innerHTML = '';
  c.insertAdjacentHTML('afterbegin', renderRaw(d));
});
es.addEventListener('report', ev => {
  const d = JSON.parse(ev.data);
  reportCount++; bufferCount = 0;
  document.getElementById('report-count').textContent = reportCount;
  document.getElementById('buffer-count').textContent = 0;
  document.getElementById('last-report').textContent = new Date().toLocaleTimeString();
  const c = document.getElementById('reports-container');
  if (c.querySelector('.empty-state')) c.innerHTML = '';
  c.insertAdjacentHTML('afterbegin', renderReport(d));
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(_HTML)
