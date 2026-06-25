# Scenario A — Shell in Container

## What it does

Runs the `falcosecurity/event-generator` as a Kubernetes Job in the `prod`
namespace. The job executes the `syscall.ExecInsideContainer` action, which
spawns a shell inside a running container using a simulated `kubectl exec`
pattern. This reliably fires Falco's built-in **Terminal shell in container**
rule.

## Expected Falco alert

```
Terminal shell in container (user=root shell=sh parent=<parent>
  cmdline=sh container=<id> image=falcosecurity/event-generator
  k8s_ns=prod k8s_pod=event-generator-<suffix>)
```

Priority: **WARNING**

## How the agent processes it

1. Fetches the single alert from `/buffer`
2. Looks up pod metadata for `event-generator-*` in namespace `prod`
3. Runs Prometheus queries — expects minimal activity (single shell exec)
4. Produces a triage report with:
   - `severity: MEDIUM` (single low-priority alert, no corroborating signals)
   - `decision: ESCALATE` (if confidence < 70) or `SUPPRESS` (if confidence >= 70
     and no anomalies)
   - `recommended_action`: "Review whether an engineer ran kubectl exec against a
     prod pod; if unplanned, escalate to the on-call team."

## Notes

- The alert references the **event-generator pod**, not the `webapp` pod.
  This is expected — the event-generator creates its own execution context.
  The agent correlates on namespace, so the `prod` context is still captured.
- Scenario A is intentionally simple: one alert, no multi-step pattern,
  expected low confidence. Use Scenario B for the ESCALATE demonstration.
