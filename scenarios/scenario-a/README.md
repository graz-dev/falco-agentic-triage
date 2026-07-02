# Scenario A — Exec into a Production Pod

## What it does

A Kubernetes Job in namespace `prod` performs a real `kubectl exec` into the running
`webapp` pod, using a ServiceAccount granted `pods/exec`. The exec is an API call the
audit log captures, and the command it runs inside the container (`cat /etc/shadow`)
trips a syscall rule. One action, two detection sources, the same target pod.

This is the smallest scenario that crosses both pipelines — useful to see the agent
correlate an audit-log event with an in-container syscall event without a full attack
chain to lean on.

## Expected alerts

| Source | Rule | Priority | Pod |
|--------|------|----------|-----|
| k8saudit | `Attach/Exec Pod` | NOTICE | `webapp-*` (the exec target) |
| syscall | `Read sensitive file untrusted` | WARNING | `webapp-*` (the `cat /etc/shadow`) |
| syscall | `Contact K8S API Server From Container` | NOTICE | `event-generator-*` (the tool pod talking to the API) |

The third alert is a side effect of driving the attack from inside the cluster: the
exec-driver pod itself contacts the API server, which Falco flags. It is honest noise —
an attacker's tooling reaching the API is a real signal — and it shows up on a different
pod than the target.

> No `-it` (no TTY) on the exec: that is why you see `Read sensitive file untrusted`
> (the reader is `cat`) rather than `Terminal shell in container` (which requires an
> attached terminal). See `infra/falco-operator/k8saudit/README.md` for the audit wiring.

## How the agent processes it

The webhook-receiver buffers the alerts (prod is in scope) and, on the next 30-second
tick, triggers the agent. The agent runs a fixed, read-only chain:

| Tool | What it does |
|------|--------------|
| `get_alert_buffer` | Reads the batch — rules, priorities, timestamps, pods, across both sources |
| `get_pod_events` | Pulls lifecycle events for the pod (restarts, crashes) for context |
| `post_triage_result` | Submits the structured report; the receiver normalizes it and flushes the buffer |

It has no other tools — no metrics, no cluster reads beyond pod events. The receiver's
deterministic floor then sets the final severity and decision from the actual buffer.

## Expected verdict

A NOTICE exec plus a WARNING file read is real corroboration but short of a full
intrusion chain, so expect **MEDIUM / ESCALATE**: enough signal to put it in front of a
human, not enough to call it an incident on its own. The analyst confirms whether the
exec was authorized.

## Value

- One pre-built report instead of pivoting by hand between the audit log and runtime alerts.
- The two sources are already joined: "someone exec'd into this pod, and inside it a
  sensitive file was read" — a link no single rule makes.
- The ESCALATE comes with its rationale, so the analyst validates rather than investigates.
