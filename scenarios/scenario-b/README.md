# Scenario B — Multi-Alert Attack Sequence

## What it does

Runs three `falcosecurity/event-generator` actions in sequence within a single
30-second triage window, simulating a realistic multi-stage intrusion:

| Time | Action | Falco Rule | Priority |
|------|--------|------------|----------|
| T+0s | `syscall.ReadSensitiveFileUntrusted` | Read sensitive file untrusted | WARNING |
| T+3s | `syscall.ExecInsideContainer` | Terminal shell in container | WARNING |
| T+6s | `syscall.WriteBelowEtcDirectory` | Write below etc | ERROR |

## Attack narrative

This sequence maps to a realistic container intrusion:

1. **Reconnaissance** — attacker reads `/etc/shadow` or SSH keys to harvest credentials
2. **Interactive access** — attacker spawns a shell to explore the environment
3. **Persistence** — attacker writes to `/etc/cron.d` or `/etc/passwd` to establish a foothold

All three events happen on the **same pod** within **9 seconds**, well inside the
30-second triage window. The agent should detect this as a coherent pattern.

## Expected triage output

```json
{
  "severity": "HIGH",
  "confidence": 88,
  "decision": "ESCALATE",
  "correlation_summary": "Three-stage intrusion pattern detected on prod workload
    in namespace prod: sensitive file read (T+0), interactive shell spawn (T+3s),
    write to /etc directory (T+6s). The sequential timing and escalating privilege
    indicators suggest active hands-on-keyboard intrusion with a persistence attempt.",
  "evidence": [
    "Read Sensitive File Untrusted fired at T+0 on event-generator pod in prod",
    "Terminal shell in container fired at T+3s on the same pod",
    "Write Below Etc fired at T+6s — ERROR priority — confirming persistence attempt"
  ],
  "recommended_action": "Immediately review the event-generator pod in namespace prod.
    Confirm whether this execution was authorized. If unplanned, isolate the workload
    and begin forensic investigation of /etc modifications."
}
```

## Why confidence is high

- Three different rule types on the same pod in under 10 seconds
- Escalating severity: WARNING → WARNING → ERROR
- Sequential timing consistent with hands-on-keyboard activity
- No legitimate reason for a prod workload to read shadow files AND spawn a shell
  AND write to /etc within a single 30-second window
