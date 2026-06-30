# Scenario B — Multi-Step Attack Sequence

## What it does

A Kubernetes Job in namespace `prod` drives a hands-on-keyboard intrusion against the
`webapp` pod, all from one attacker tool pod and all inside a single 30-second window.
It `kubectl exec`s into the target twice and reads a Secret through the API, which lights
up **both** detection sources with escalating severity:

| Step | Action | Source | Rule | Priority |
|------|--------|--------|------|----------|
| 1 | `kubectl exec … cat /etc/shadow` | k8saudit + syscall | `Attach/Exec Pod` / `Read sensitive file untrusted` | NOTICE / WARNING |
| 2 | `kubectl exec … cp /bin/cat /tmp/x && /tmp/x /etc/shadow` | k8saudit + syscall | `Attach/Exec Pod` / `Drop and execute new binary in container` | NOTICE / **CRITICAL** |
| 3 | `kubectl get secret demo-secret` | k8saudit | `K8s Secret Get Successfully` | **ERROR** |

The exec-driver pod also fires `Contact K8S API Server From Container` (NOTICE) on itself
for each API call — the attacker tooling reaching the API. Honest noise, on a different
pod than the target.

## Attack narrative

Credential access from inside a pod (`/etc/shadow`), a binary that isn't part of the image
being dropped and run (foothold), and a Secret pulled through the API. The API exec and the
in-container syscalls share the same target and window, so they read as one operation rather
than three unrelated alerts.

## How the agent processes it

Same fixed read-only chain as Scenario A — `get_alert_buffer` → `get_pod_events` →
`post_triage_result` (three MCP tools, nothing else). The agent drafts the multi-step
narrative across both sources. Then the receiver's deterministic floor takes over: it reads
the actual buffer and, because a CRITICAL alert (`Drop and execute…`) and an ERROR alert
(`K8s Secret Get…`) are present, forces the verdict to **CRITICAL / ESCALATE** regardless of
what the model proposed.

That split is the point of the scenario: the model writes the story, the code owns the
decision. A small local model's narrative is best-effort — it may mis-attribute an alert to
the wrong pod — but the severity and the escalation never depend on it.

## Expected verdict

**CRITICAL / ESCALATE**, high confidence. The combination of an untrusted binary, a
credential-file read, and a Secret API access on one target in one window is the strongest
signal the demo produces, and the floor guarantees it escalates.

## Value

- Three-plus correlated signals across two pipelines collapsed into one report an analyst
  can hand to IR.
- The recommended action already names the artefacts to preserve (the `/etc/shadow` reads,
  the dropped `/tmp/x`, the `demo-secret` access).
- The escalation is deterministic — a CRITICAL-priority alert can never be quietly suppressed.
