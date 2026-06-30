# Falco Agentic Alert Triage — Demo

## 1. Overview

This demo runs an **assistive, bounded** agentic triage workflow on a local
Kubernetes cluster. Falco detects runtime threats from two sources — syscalls and the
Kubernetes audit log — and Falcosidekick forwards every alert to a lightweight receiver.
A triage agent (built with Google ADK, deployed via kagent) accumulates alerts over a
30-second window, correlates them with Kubernetes context, and produces a structured
triage report that lands on a small web UI — the stand-in for Slack or PagerDuty.

The agent is deliberately **assistive, not autonomous**. It never takes remediation
actions, and it never decides the verdict on its own: a deterministic layer in the
receiver enforces the severity and the escalation rule. The model writes the narrative;
the code owns the decision. Every report is reviewed by a human.

The running example is a hands-on-keyboard pattern that spans both detection sources:
someone runs `kubectl exec` into a production pod (audit log), then inside it reads
`/etc/shadow` and runs a binary that isn't part of the image (syscalls), and pulls a
Secret through the API (audit log). No single rule sees the whole thing; the agent does,
because all of it lands in one window.

---

## 2. Architecture

```
[kubectl exec / API call] ──▶ kube-apiserver audit ──▶ [Falco k8saudit Deployment]
[in-container activity]   ──▶ syscalls           ──▶ [Falco syscall DaemonSet]
                                                            │
                                                            ▼  JSON alert (http_output)
                                                     [Falcosidekick]
                                                            │  POST /ingest
                                                            ▼
                                                   [webhook-receiver]
                                            ┌──────────────────────────┐
                                            │  raw_alerts deque         │ ─▶ SSE ─▶ UI Tab 1
                                            │  alert_buffer deque       │ (user-workload ns only)
                                            │  triage_reports deque     │ ─▶ SSE ─▶ UI Tab 2
                                            │  /history (page hydration)│
                                            │  /mcp (3 agent tools)     │
                                            │  30s trigger loop (A2A)   │
                                            └──────────────────────────┘
                                                            │  A2A message/send (every 30s when buffered)
                                                            ▼
                                                   [triage-agent (kagent)]
                                                            │  reads via MCP:
                                                            ├─ get_alert_buffer
                                                            └─ get_pod_events
                                                            │  POST /mcp post_triage_result
                                                            ▼
                                                   [webhook-receiver]
                                            (normalize + deterministic floor, store, flush)
```

**Falco — syscall DaemonSet** detects in-container runtime threats via `modern_ebpf`
(shell spawns, sensitive file reads, untrusted binaries).

**Falco — k8saudit Deployment** is a second, plugins-only Falco instance in its own
namespace. The kube-apiserver ships audit events to it (kubectl exec, secret reads,
RBAC changes, privileged pods). Keeping it separate from the DaemonSet keeps the audit
plugin out of the syscall instance.

**Falcosidekick** forwards every alert from both instances to the receiver's `/ingest`.

**webhook-receiver** (FastAPI) keeps an in-memory raw alert store and a triage buffer
(scoped to user-workload namespaces). It serves a Server-Sent Events stream for the UI,
a `/history` endpoint for page-load hydration, and an MCP endpoint exposing exactly three
tools. A loop polls the buffer every 30 seconds and, when it is non-empty, triggers the
agent over kagent's A2A interface with a fresh session per cycle.

**triage-agent** (kagent + Google ADK) reads the buffer via `get_alert_buffer`, pulls pod
lifecycle events via `get_pod_events`, drafts a structured report, and posts it back via
`post_triage_result` — which flushes the buffer. It never calls a mutating K8s API. Tool
transport is MCP `STREAMABLE_HTTP`.

**agentgateway** proxies the agent's LLM calls from inside the cluster to LM Studio on the
host Mac, reaching it at `host.docker.internal:1234`.

---

## 3. Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| kind | v0.32.0 | https://kind.sigs.k8s.io/docs/user/quick-start/ |
| kubectl | latest stable | https://kubernetes.io/docs/tasks/tools/ |
| helm | v3.x | https://helm.sh/docs/intro/install/ |
| Docker Desktop (Mac) | latest | https://www.docker.com/products/docker-desktop/ |
| LM Studio | latest | https://lmstudio.ai/download — see §5a |

```bash
make prereqs
```

**Kubernetes version note:** this demo uses `kindest/node:v1.35.5` because kind v0.32.0
ships pre-built node images up to v1.35.5. Kubernetes 1.35 is well above the Falco
Operator minimum. The kubeadm config patches use `v1beta3`; to move to a newer node image,
update the sha256 in `kind-config.yaml` and the kubeadm patch `apiVersion` accordingly.

**Linux note:** Docker on Linux does not resolve `host.docker.internal` automatically. Add
`--add-host=host.docker.internal:host-gateway` to your Docker daemon configuration so the
agentgateway backend can reach LM Studio on the host.

---

## 4. Quick Start

```bash
git clone <repo>
cd falco-agentic-triage

# Step 1: Start LM Studio, load qwen2.5-7b-instruct-mlx, start the server on :1234
#         (detailed instructions in §5a)

# Step 2: If your model id differs, paste it into BOTH:
#   infra/agentgateway/llm-backend.yaml  →  spec.ai.groups[0].providers[0].openai.model
#   infra/kagent/model-config.yaml       →  spec.model

# Step 3: Verify LM Studio is reachable
make check-lmstudio

# Step 4: Create the cluster and install everything (~6–10 min)
make setup

# Step 5: Open the UI
make ui          # http://localhost:8080

# Step 6: Run the single-action scenario (real kubectl exec → audit + syscall alerts)
make scenario-a
# A correlated report appears in the Triage Reports tab within ~90–150s (LLM inference time)

# Step 7: Run the multi-step attack sequence
make clean-scenario
make scenario-b
```

---

## 5. Detailed Installation Walkthrough

### Install the tooling

```bash
brew install kind kubectl helm     # macOS
kind version                       # should print v0.32.0
```

### Create the cluster

```bash
make cluster
```

This runs `kind create cluster --name falco-triage-demo --config kind-config.yaml`. The
single control-plane node has:
- Kubernetes Audit Log enabled, with the audit policy and webhook config mounted at creation
- The audit webhook pointed at the k8saudit Falco instance via NodePort 30765
- NodePort 30080 → host port 8080 (webhook-receiver UI)

### Install all infrastructure

```bash
make infra
```

This runs four steps in order. The order matters: the receiver comes up before kagent so
the agent's MCP connection is accepted on the first attempt.

**Step 1 — Falco Operator (Helm chart 0.3.0 = app 0.4.0)**

```bash
helm repo add falcosecurity-charts https://falcosecurity.github.io/charts
helm upgrade --install falco-operator falcosecurity-charts/falco-operator \
  --namespace falco-operator --create-namespace --version 0.3.0 --wait
```

Then applies the Falco CRs and the k8saudit stack:
```bash
kubectl apply -f infra/falco-operator/rulesfiles/rulesfile-default.yaml
kubectl apply -f infra/falco-operator/plugin-container.yaml
kubectl apply -f infra/falco-operator/falco-http-output-config.yaml
kubectl apply -f infra/falco-operator/falco-instance.yaml
kubectl apply -f infra/falco-operator/falcosidekick-component.yaml
kubectl apply -f infra/falco-operator/k8saudit/k8saudit-stack.yaml
```

Use chart **0.3.0** (app 0.4.0). The older chart 0.2.0 (app 0.3.0) emits legacy
`engine.ebpf`/`grpc_output` blocks that Falco 0.44 flags as a schema warning. `http-output`
is a `config.d` drop-in that enables JSON output and HTTP forwarding; it is mounted into the
Falco pods at startup. See `infra/falco-operator/k8saudit/README.md` for the audit wiring.

**Step 2 — agentgateway (v1.3.0)**

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
helm upgrade --install agentgateway-crds oci://cr.agentgateway.dev/charts/agentgateway-crds \
  --version 1.3.0 --namespace agentgateway-system --create-namespace --wait
helm upgrade --install agentgateway oci://cr.agentgateway.dev/charts/agentgateway \
  --version 1.3.0 --namespace agentgateway-system --create-namespace --wait
kubectl apply -f infra/agentgateway/gateway.yaml
kubectl apply -f infra/agentgateway/llm-backend.yaml
```

**Step 3 — webhook-receiver**

```bash
docker build -t webhook-receiver:latest webhook-receiver/
# image is loaded into the kind node, then:
kubectl apply -f webhook-receiver/k8s/rbac.yaml
kubectl apply -f webhook-receiver/k8s/deployment.yaml
kubectl apply -f webhook-receiver/k8s/service.yaml
```

The receiver's ServiceAccount has read-only `events` access (for `get_pod_events`) and
nothing else.

**Step 4 — kagent (v0.9.10)**

```bash
helm upgrade --install kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
  --version 0.9.10 --namespace kagent --create-namespace --wait
helm upgrade --install kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent \
  --version 0.9.10 --namespace kagent --create-namespace \
  --set k8s-agent.enabled=false --set kgateway-agent.enabled=false
kubectl apply -f infra/kagent/model-config.yaml
kubectl apply -f infra/kagent/remotemcpserver-webhook.yaml
kubectl apply -f infra/kagent/triage-agent.yaml
```

The triage-agent uses **one** MCP server connection — `webhook-receiver-mcp` at `/mcp` —
exposing exactly three tools: `get_alert_buffer`, `get_pod_events`, and `post_triage_result`.

### Validation checklist

```bash
# Falco — both instances Ready, no engine.ebpf schema warning
kubectl get pods -n falco
kubectl get pods -n falco-k8saudit
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i 'engine.ebpf' || echo "clean"

# k8saudit plugin loaded and audit source open
kubectl logs -n falco-k8saudit -l app.kubernetes.io/name=falco-k8saudit -c falco | grep -i k8saudit

# agentgateway / kagent
kubectl get pods -n agentgateway-system
kubectl get pods -n kagent
kubectl get agent -n kagent

# webhook-receiver UI
curl -s http://localhost:8080/buffer

# LM Studio reachable from inside the cluster
kubectl run test-lmstudio --rm -i --restart=Never --image=curlimages/curl:8.8.0 -- \
  curl -s http://host.docker.internal:1234/v1/models
```

---

## 5a. LM Studio Setup (Required Before `make setup`)

LM Studio is a desktop app that downloads open-weight models and serves them locally over
an OpenAI-compatible API on `localhost:1234`. The demo uses it to run the model entirely on
your machine — no API keys, no cloud, no telemetry leaving the host. The agent inside the
cluster reaches it through agentgateway.

### Step 1 — Install
Download from https://lmstudio.ai/download, install, and launch.

### Step 2 — Download the model
Open the model search (`Cmd+Shift+M`) and download **`qwen2.5-7b-instruct-mlx`**. On Apple
Silicon the MLX build is the fast path; ~8 GB RAM is enough for the 7B. Qwen2.5-Instruct is
used here because it is reliable at structured output and multi-step tool-calling, which this
workflow leans on.

### Step 3 — Load it
Click the model in **My Models** and wait for **Loaded**.

### Step 4 — Start the server
**Developer → Local Server → Start**. Status becomes **Running** at `http://localhost:1234`.
Leave it running for the whole demo (you can minimize the window).

### Step 5 — Confirm the model id
The id shown in the server tab must match what the manifests expect
(`qwen2.5-7b-instruct-mlx`). If yours differs, paste the exact string into both
`infra/agentgateway/llm-backend.yaml` and `infra/kagent/model-config.yaml`. A mismatch
returns a 404 from agentgateway.

```bash
make check-lmstudio          # lists the loaded models
```

### Alternative: Ollama
`ollama pull qwen2.5:7b`, `ollama serve` (endpoint `http://localhost:11434/v1`). Point
`llm-backend.yaml` (`host`/`port`/`path`) and `model-config.yaml` (`spec.model: qwen2.5:7b`)
at it and re-apply.

### Choosing a bigger model
The 7B is the floor for this 3-tool chain. If you have the RAM, a larger instruct model
(Qwen2.5-14B or -32B) is measurably steadier on long tool chains and schema adherence.
Swap it the same way: load it in LM Studio, copy the id into both manifests, then
`kubectl rollout restart deployment/triage-agent -n kagent`. Tool-calling reliability — not
raw knowledge — is what matters for this workload, so prefer instruct models trained for
function-calling over base or chat-only variants.

---

## 6. Scenarios

### Scenario A: Exec into a Production Pod

**Run it:**
```bash
make scenario-a
```

**What happens:** a Job in namespace `prod` performs a real `kubectl exec` into the `webapp`
pod, using a ServiceAccount granted `pods/exec`. The exec itself is an API call the audit log
captures, and the command it runs inside the container trips a syscall rule. So one action
produces alerts from **both** detection sources on the same pod:

| Source | Rule | Priority | Pod |
|--------|------|----------|-----|
| k8saudit | `Attach/Exec Pod` | NOTICE | `webapp-*` (the exec target) |
| syscall | `Read sensitive file untrusted` | WARNING | `webapp-*` (the `cat /etc/shadow`) |
| syscall | `Contact K8S API Server From Container` | NOTICE | `event-generator-*` (the tool pod) |

The third alert is honest noise: the exec-driver pod itself contacts the API server, which
Falco flags. No `-it` is used, so the syscall rule is `Read sensitive file untrusted` (reader
is `cat`) rather than `Terminal shell in container` (which needs a TTY).

**Alert flow:**
1. The apiserver ships the exec audit event to the k8saudit Falco instance; the syscall
   instance fires on the in-container file read.
2. Both alerts reach Falcosidekick, which POSTs them to `/ingest`; the receiver buffers them
   (prod is in scope).
3. The 30s trigger loop invokes the agent over A2A.
4. The agent calls `get_alert_buffer`, then `get_pod_events` for the pod's lifecycle context.
5. The agent calls `post_triage_result`; the receiver normalizes it, applies the deterministic
   floor, stores the report, and flushes the buffer.

An exec from the API plus a sensitive-file read inside the pod is real corroboration but short
of a full intrusion chain. Expect **MEDIUM / ESCALATE**: enough to put it in front of a human,
who confirms whether the exec was authorized.

### Scenario B: Multi-Step Attack Sequence

**Run it:**
```bash
make clean-scenario
make scenario-b
```

**What happens:** one attacker tool pod drives a multi-step intrusion against `webapp`,
within a single window, lighting up both sources with escalating severity.

| Step | Action | Source | Rule | Priority |
|------|--------|--------|------|----------|
| 1 | exec → `cat /etc/shadow` | k8saudit / syscall | `Attach/Exec Pod` / `Read sensitive file untrusted` | NOTICE / WARNING |
| 2 | exec → drop & run a binary | k8saudit / syscall | `Attach/Exec Pod` / `Drop and execute new binary in container` | NOTICE / **CRITICAL** |
| 3 | `kubectl get secret demo-secret` | k8saudit | `K8s Secret Get Successfully` | **ERROR** |

The agent drafts the multi-step narrative; the deterministic floor — which keys on the CRITICAL
and ERROR priorities present in the buffer — forces **CRITICAL / ESCALATE** regardless of what
the model proposed. The model writes the story; the code owns the decision.

> The triage report is JSON: `window_start`/`window_end`, `alert_count`, `affected_workloads`
> (pod, namespace, image, alert timeline), `correlation_summary`, `severity`, `confidence`,
> `evidence`, `recommended_action`, `decision`, `suppression_reason`. The UI renders it as a
> card with a severity badge and a confidence bar.

---

## 7. Why This Agent — Operator Value

### What the agent replaces

Without an agent, a Falco alert pages an analyst who must, by hand: read the raw JSON, run
`kubectl get`/`describe`/`get events` on the pod, recall what the rule means and whether it
has fired before, cross-reference other alerts for a multi-step pattern, and write up whether
to wake the IR team. That is 15–30 minutes per alert, needs real Kubernetes fluency, and gets
worse with volume and fatigue.

### What the agent does instead

Within 30–90 seconds of the window closing, the agent runs a small fixed tool chain:

| Step | Tool | What it learns |
|------|------|----------------|
| Fetch the batch | `get_alert_buffer` | Rules, priorities, timestamps, pod/namespace/image — across both sources |
| Lifecycle context | `get_pod_events` | Restarts, CrashLoops, OOMKills — was the pod already unhealthy? |
| Submit the report | `post_triage_result` | Structured ESCALATE/SUPPRESS with a narrative |

The analyst opens the UI to a pre-built report — correlation narrative, severity badge,
confidence, recommended action. The job becomes **validation**, not investigation.

### Data sources and coverage

| Source | How it reaches the agent | What it covers |
|--------|--------------------------|----------------|
| Falco syscall rules | `get_alert_buffer` | In-container behaviour: file reads, shell spawns, untrusted binaries |
| Falco k8saudit rules | `get_alert_buffer` | API actions: kubectl exec, secret reads, RBAC changes. Rules with "K8s" or "Attach/Exec" in the name come from this pipeline |
| K8s lifecycle events | `get_pod_events` | Restarts, OOMKills, scheduling failures — context on prior health |

**What is not covered:** deep forensic enrichment (full audit payload, source IP, identity
chains) belongs to a log pipeline (Loki, OpenSearch, Elastic) and to the IR team after
escalation. The agent triages; it does not investigate to ground truth.

### What the agent deliberately does not do

- **No remediation.** It never deletes pods, edits network policies, rotates secrets, or calls
  any mutating K8s API. Every ESCALATE waits for a human.
- **No detection.** Falco detects; the agent triages what Falco found.
- **No tuning.** It does not modify rules or suppress future alerts.
- **No unilateral verdict.** The model proposes a severity and decision; a deterministic floor
  in the receiver can only make the verdict *safer* (raise severity, force escalation), never
  soften it.

---

## 8. Design Decisions and Production Alternatives

**Who decides.** The model drafts the narrative and proposes severity/confidence/decision, but
`_normalize_report` in `main.py` owns the verdict. It reads the actual buffer and forces
CRITICAL when any Critical alert is present, HIGH when an ERROR is present or three-plus
distinct rules hit one pod, and ESCALATE when confidence is under 70 or any ERROR/CRITICAL is
present. The floor can only raise, never lower. This is deliberate: the model is
nondeterministic, so the safety-critical call stays in code you can read and replay.

**Alert ingestion.** The receiver polls its own buffer every 30 seconds (`asyncio` loop, 60s
initial delay + 60s cooldown). For production: a queue (Redis Streams, NATS, Kafka) or a gRPC
stream. Polling is chosen here for auditability — each cycle is one discrete, logged event.

**In-memory state.** `deque(maxlen=100)`. For production: Redis (multi-replica receiver) or a
proper event log.

**LLM provider.** LM Studio + a local model keeps everything offline. The `ModelConfig`
abstraction sits between the agent and the provider, so pointing at Vertex AI, Bedrock, or
self-hosted vLLM needs no agent code change — only the `model-config.yaml` and the
agentgateway backend.

**LLM function-calling reliability — lessons that shaped the build.** A 7B local model is on
the small side for a multi-step tool chain, and a few behaviours drove the design:

- *Context length is the main lever.* As the per-cycle context grows, small models drift from
  emitting a tool call to writing the report as free text. The tool chain is kept to two read
  tools, and the buffer projection handed to the model is deliberately compact (`get_alert_buffer`
  returns up to 8 deduplicated alerts, each output trimmed to ~120 chars). Richer projections
  were tried and measurably degraded correlation on the 7B — keep the context lean.
- *Session accumulation is a silent failure.* kagent reuses one A2A `sessionId` by default, so
  history grows every cycle until function-calling collapses. The trigger sends a fresh
  `uuid4()` `sessionId` per cycle (`_invoke_agent_sync`), keeping each triage independent.
- *Tool arguments arrive as JSON strings.* ADK passes `function.arguments` as a JSON-encoded
  string; the `/mcp` handler detects and parses it (`isinstance(arguments, str)` guard).
- *Field naming is nondeterministic.* The model varies `pod`/`pod_name`/`k8s.pod.name` etc.;
  `_normalize_report` maps every observed variant to the canonical schema, and reconstructs
  `affected_workloads` from the buffer if the model omits them.
- *Small models loop.* A model can call `post_triage_result` repeatedly in one cycle. The first
  call flushes the buffer and stores the report; a guard makes every subsequent call on an empty
  buffer a no-op, so the UI never floods with empty reports.

If the agent fails to post a report in a cycle, the buffer stays non-empty and the next cycle
retries. The system self-corrects.

**Agent triggering.** The fixed 30s window is the teaching point. For production:
threshold-based (N alerts in M seconds), a severity fast-path (CRITICAL triggers immediately),
or a sliding window with deduplication.

**Observability.** agentgateway emits OTel traces per LLM call; this demo does not wire a
collector. For production, add one and combine with kagent's spans for end-to-end visibility.

**Least privilege.** The agent reaches the LLM only through agentgateway and the cluster only
through three read-only MCP tools. The receiver's ServiceAccount can read `events` and nothing
else. No component in the triage path holds a write verb against the cluster.

**Falco Operator teardown order.** When uninstalling without `kind delete cluster`, delete
artifact CRs (Rulesfile, Plugin) first, then instance CRs (Falco, Component), then the Helm
release — reversing it orphans finalizers. `make teardown` uses `kind delete cluster`, which
sidesteps this.

---

## 9. Troubleshooting

**Falco pod in CrashLoopBackOff**
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco
```
`modern_ebpf` needs kernel ≥ 5.8. Docker Desktop for Mac runs a 6.x kernel (fine).

**k8saudit plugin not receiving events**
```bash
kubectl logs -n falco-k8saudit -l app.kubernetes.io/name=falco-k8saudit -c falco | grep -i k8saudit
kubectl get svc falco-k8saudit-webhook -n falco-k8saudit
```
Confirm the audit webhook in `infra/audit-webhook-config.yaml` targets
`http://localhost:30765/k8s-audit` and that the NodePort Service exists.

**agentgateway cannot reach LM Studio**
```bash
kubectl run test-lmstudio --rm -i --restart=Never --image=curlimages/curl:8.8.0 -- \
  curl -sv http://host.docker.internal:1234/v1/models
```
On Linux, add `--add-host=host.docker.internal:host-gateway` to the Docker daemon. On Mac,
confirm Docker Desktop is running.

**Agent produces no report**
```bash
kubectl logs -n kagent -l app=triage-agent --tail=50
```
Check that the `ModelConfig` `baseUrl` matches the agentgateway service and that the model id
matches LM Studio's server tab exactly. A low-confidence or failed cycle leaves the alerts in
the buffer; the next cycle retries within ~90 seconds.

**Reports are noisy or fragmented right after `make setup`**
Bootstrap creates namespaces and reads Secrets, which themselves generate k8saudit alerts
(`Create Disallowed Namespace`, agentgateway's own Secret reads). If you trigger a scenario
while that noise is still draining, the agent may triage the bootstrap alerts in separate
cycles. Wait until the buffer is quiet (`curl -s localhost:8080/buffer` returns `[]`) before
running a scenario, and run the scenario as a single burst.

**Falcosidekick not forwarding**
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick
```
Confirm the webhook address (`webhook-receiver.demo.svc.cluster.local:8000/ingest`) and that
`minimumpriority` is `notice` (so NOTICE-level audit/exec alerts pass through).

**Note on http_output coupling:** Falco forwards over HTTP to Falcosidekick by service DNS. If
Falcosidekick is restarting when an alert fires, that alert is dropped — acceptable for a demo,
but in production you would buffer between detection and fan-out.

---

## 10. References

- Falco documentation: https://falco.org/docs/
- Falco Operator: https://github.com/falcosecurity/falco-operator
- Falcosidekick: https://github.com/falcosecurity/falcosidekick
- k8saudit plugin: https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit
- event-generator: https://github.com/falcosecurity/event-generator
- kagent: https://kagent.dev/
- agentgateway: https://agentgateway.dev/
- kind: https://kind.sigs.k8s.io/
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
- NIST SP 800-61 Rev. 3 (2025): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- DZone Refcard: *(link to be added after publication)*
