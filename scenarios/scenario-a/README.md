# Scenario A — Shell in Container

## What it does

Runs the `falcosecurity/event-generator` as a Kubernetes Job in the `prod`
namespace. The job calls `syscall.RunShellUntrusted`, which spawns an
untrusted shell inside a running container. This fires Falco's built-in
**Terminal shell in container** rule.

## Expected Falco alert

```
Terminal shell in container (user=root shell=sh parent=<parent>
  cmdline=sh container=<id> image=falcosecurity/event-generator
  k8s_ns=prod k8s_pod=event-generator-<suffix>)
```

Priority: **WARNING**

---

## How the agent processes this scenario

### Without the agent

An analyst receiving this alert must:

1. Identify the pod from the raw Falco JSON
2. Run `kubectl describe pod event-generator-<suffix> -n prod` to check image,
   security context, and owner (is it a Job? a Deployment? is it expected?)
3. Check `kubectl get events -n prod` for any CrashLoop or restart history
4. Open Grafana, find the pod, check CPU/memory — any spike? Any previous
   anomalies?
5. Decide: was this a legitimate `kubectl exec` by an engineer? Or something
   suspicious?

This takes **10–20 minutes** and requires knowing which kubectl commands to
run, what "normal" looks like for this workload, and whether this rule fires
often enough to be noise.

### With the agent (30–90 seconds)

The agent calls four tools automatically:

| Tool | What it finds |
|------|---------------|
| `get_alert_buffer` | Single WARNING alert: "Terminal shell in container" on `event-generator-*` in `prod` |
| `k8s_get_resources` | Pod image = `falcosecurity/event-generator`, owner = Job, runs as root, `privileged: true` |
| `get_pod_events` | Pod `Started`, `Completed` — no CrashLoop, no OOMKill, no restarts |
| `get_pod_metrics` | CPU peak ~0.01 cores, memory ~8 MB — minimal resource use |

The agent correlates: one alert, no lifecycle anomalies, no resource spike,
transient Job workload. With a single WARNING and no corroborating signals,
confidence stays below 70% → automatic ESCALATE per the constraint, with a
narrative like:

> "A single terminal shell event was detected on a transient event-generator
> Job in namespace prod. No corroborating signals — no CrashLoop history, no
> sensitive file reads, no resource spike. The event may represent a scheduled
> test or an authorized exec. Confidence is insufficient to suppress without
> human confirmation."

### Value delivered

- **Time saved:** 10–20 minutes of manual investigation → 30–90 seconds
- **Context pre-built:** Pod image, owner, lifecycle, and metrics already
  gathered and explained — analyst confirms or overrides in seconds
- **ESCALATE with rationale:** The analyst sees WHY the agent couldn't suppress
  (single alert, low confidence), not just a raw alert with no guidance

---

## Notes

- The alert references the **event-generator pod** itself, not the `webapp` pod.
  This is expected — the event-generator creates its own execution context.
  The agent correlates on namespace, so the `prod` context is captured.
- Scenario A is intentionally simple: one alert, no multi-step pattern,
  expected low confidence. It demonstrates the ESCALATE path and shows the
  analyst what the agent collects even for ambiguous cases.
- Use **Scenario B** for the high-confidence multi-alert ESCALATE demonstration.
