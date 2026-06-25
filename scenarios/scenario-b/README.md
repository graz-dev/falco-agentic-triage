# Scenario B — Multi-Alert Attack Sequence

## What it does

Runs three `falcosecurity/event-generator` actions in sequence within a single
30-second triage window, simulating a realistic multi-stage container intrusion:

| Time | Action | Falco Rule | Priority |
|------|--------|------------|----------|
| T+0s | `syscall.ReadSensitiveFileUntrusted` | Read sensitive file untrusted | WARNING |
| T+3s | `syscall.RunShellUntrusted` | Terminal shell in container | WARNING |
| T+6s | `touch /etc/falco-demo-persistence-marker` | Write below etc | ERROR |

## Attack narrative

This sequence maps to a realistic container intrusion pattern:

1. **Reconnaissance (T+0)** — process reads `/etc/shadow` or SSH key files to
   harvest credentials or understand the environment
2. **Interactive access (T+3)** — attacker spawns a shell to explore and pivot
3. **Persistence (T+6)** — attacker writes to `/etc/` to establish a foothold
   that survives container restarts

All three events happen on the **same pod** within **9 seconds**, well inside the
30-second triage window. This is the core correlation test.

---

## How the agent processes this scenario

### Without the agent

An analyst receiving three separate Falco alerts must:

1. Get paged (potentially three separate notifications)
2. For each alert, run `kubectl get pod`, `kubectl describe`, check events
3. Manually notice that all three alerts share the same pod name and namespace
4. Manually build a timeline and recognize the pattern: file read → shell → /etc write
5. Assess whether the 9-second gap between events is consistent with scripted
   attack activity vs. coincidence
6. Query Prometheus for CPU/memory anomalies in the same window
7. Write an incident summary with enough context for the IR team to act immediately

This takes **30–45 minutes** (three separate alerts × 10–15 min each), and
the correlation step is entirely manual — an analyst handling multiple incidents
simultaneously may process the three alerts independently and miss the pattern.

### With the agent (60–120 seconds)

The agent correlates all three alerts in a single cycle because they arrived
within the same 30-second buffer window:

| Tool | What it finds |
|------|---------------|
| `get_alert_buffer` | 3 alerts on the same pod within 9 seconds: WARNING → WARNING → ERROR |
| `k8s_get_resources` | Pod image = `falcosecurity/event-generator`, runs as root, `privileged: true`, owner = Job in `prod` |
| `get_pod_events` | Pod `Started`, `Completed` normally — no CrashLoop, confirming the actions were deliberate |
| `get_pod_metrics` | CPU peak ~0.2 cores, memory ~7 MB, small network TX — container was active during the alert window |

The agent recognizes the multi-step pattern, computes high confidence (>90%),
and produces a report like:

```json
{
  "severity": "HIGH",
  "confidence": 95,
  "decision": "ESCALATE",
  "correlation_summary": "Three-stage intrusion pattern on event-generator-<suffix>
    in prod within a 9-second window: sensitive file read (T+0, reconnaissance),
    interactive shell (T+3, active access), write to /etc (T+6, persistence attempt).
    K8s events confirm the container completed normally — actions were deliberate.
    Prometheus confirms the container was active (CPU peak 0.2 cores) during the
    alert window. The sequential timing and escalating severity are consistent with
    scripted hands-on-keyboard intrusion.",
  "prometheus_anomalies": ["CPU Peak: 0.2 cores; Memory Peak: 7.2 MB; Network Tx Peak: 24 B/s"],
  "evidence": [
    "Read sensitive file untrusted — credential reconnaissance",
    "Terminal shell in container 3 seconds later — interactive access confirmed",
    "Write below etc 6 seconds later — ERROR priority — persistence attempt",
    "All three events on the same pod within 9 seconds",
    "K8s events: no prior CrashLoop or restart — actions were intentional",
    "Prometheus: container CPU was 0.2 cores during the event window"
  ],
  "recommended_action": "Investigate the event-generator pod immediately. Review
    what was read from /etc/shadow or SSH key directories. Identify what was written
    to /etc/. Determine whether this Job was authorized and check the Job manifest
    for excessive privileges (privileged: true, root user)."
}
```

### Value delivered

- **Time saved:** 30–45 minutes of manual multi-alert investigation → 60–120 seconds
- **Pattern detection:** Three alerts correlated as a single attack sequence that an
  analyst might process independently
- **Multi-source narrative:** Falco alerts + K8s metadata + K8s events + Prometheus
  metrics synthesized into one paragraph the analyst can paste directly into an
  incident ticket
- **IR-ready output:** The recommended action already names the specific artefacts
  to preserve (/etc/shadow read, /etc/ write) — the analyst hands this to IR without
  needing to re-investigate

### Data sources in this scenario

| Source | What it contributes |
|--------|---------------------|
| Falco syscall rules | Detects the file read, shell spawn, and /etc write as they happen |
| K8s pod metadata | Confirms root execution, privileged context, Job ownership |
| K8s Events API | Confirms pod completed normally (no crash) — rules out accidental triggering |
| Prometheus cadvisor | Confirms the container was CPU-active during the window — corroborates deliberate action |

**Audit log note:** If this scenario included a `kubectl exec` step (which
`syscall.ExecInsideContainer` simulates), the k8saudit Falco plugin would
additionally capture the API server audit event — including the user identity
and source IP — and inject it into the alert buffer alongside the syscall alerts.
The agent already handles k8saudit-sourced alerts; the report would include the
API-level caller context in the evidence list.

---

## Why confidence is high

- Three different Falco rule types on the same pod in under 10 seconds
- Escalating priority: WARNING → WARNING → ERROR
- Sequential timing (9s total) is consistent with scripted attacker activity
- K8s events confirm the pod did not crash accidentally
- Prometheus confirms the container was active — not a stale or idle pod

The combination of behavioural signals (Falco) + infrastructure context (K8s)
+ resource evidence (Prometheus) pushes confidence above 90%, which is the
threshold at which the agent's ESCALATE decision carries enough supporting
evidence for an IR team to act without additional manual investigation.
