# Falco Agentic Alert Triage — Demo

## 1. Overview

This demo runs an **assistive, bounded** agentic triage workflow on a local
Kubernetes cluster. Falco detects runtime threats inside the cluster. Falcosidekick
fans out each alert to two destinations simultaneously. A triage agent (built with
Google ADK and deployed via kagent) accumulates alerts over a 30-second window,
correlates them with Kubernetes metadata, Prometheus metrics, and Kubernetes Audit
Log events, then produces a structured triage report that lands on a lightweight
webhook receiver UI — the stand-in for Slack or PagerDuty.

The agent is deliberately **assistive, not autonomous**. It never takes remediation
actions. Every report is reviewed by a human analyst.

The demo focuses on a three-stage attack pattern that maps to MITRE ATT&CK for
Containers: file reconnaissance (T1552.001) → interactive shell access (T1059.004)
→ persistence via /etc modification (T1546). When all three events land in the same
30-second window, the agent correlates them into a HIGH/ESCALATE decision with a
narrative identifying the intrusion sequence.

---

## 2. Architecture

```
[event-generator] → syscalls → [Falco DaemonSet]
                                      │
                                      ▼ JSON alert (http_output)
                              [Falcosidekick]
                                      │
                                 POST /ingest
                                      │
                                      ▼
                             [webhook-receiver]
                          ┌──────────────────────┐
                          │  raw_alerts deque     │ ──→ SSE → UI Tab 1
                          │  alert_buffer deque   │ (user workload ns only)
                          │  triage_reports deque │ ──→ SSE → UI Tab 2
                          │  /history endpoint    │ ──→ page-load hydration
                          │  /mcp endpoint        │ ──→ MCP tools for agent
                          └──────────────────────┘
                                      │
                    POST /mcp (get_alert_buffer, every 30s trigger)
                                      │
                                      ▼
                          [triage-agent (kagent)]
                                      │ correlates with:
                                      ├─ /mcp get_alert_buffer
                                      └─ kagent k8s_get_resources (pod metadata)
                                      │
                            POST /mcp post_triage_result
                                      │
                                      ▼
                             [webhook-receiver]
                          (stores report, flushes buffer)
```

**Falco DaemonSet** detects runtime threats via `modern_ebpf`. It ships each
alert as JSON to Falcosidekick.

**Falcosidekick** forwards every alert to the webhook-receiver's `/ingest` endpoint.

**webhook-receiver** (FastAPI) maintains an in-memory raw alert store and a triage
alert buffer (filtered to user-workload namespaces only). It exposes a Server-Sent
Events stream so the browser UI updates in real time, an MCP endpoint for the agent's
tools, and a `/history` endpoint for page-load hydration. It triggers the triage agent
every 30 seconds when the buffer is non-empty.

**triage-agent** (kagent + Google ADK) reads the alert buffer, correlates alerts with
K8s pod metadata, then produces a structured JSON triage report and posts it back via
the `post_triage_result` MCP tool, which flushes the buffer. It never calls any
mutating K8s API. Tool communication uses the MCP STREAMABLE_HTTP protocol.

**agentgateway** proxies LLM requests from inside the cluster to LM Studio running
on the host Mac, using the `host.docker.internal` hostname.

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

**Kubernetes version note:** This demo uses `kindest/node:v1.35.5` (not the
absolute latest 1.36) because kind v0.32.0 ships pre-built node images only up to
v1.35.5. Kubernetes 1.35 is fully supported and well above the Falco Operator
minimum of 1.29. The kubeadm config patches use `v1beta3` which is correct for 1.35.
To upgrade to 1.36, update the sha256 in `kind-config.yaml` and switch the kubeadm
patch `apiVersion` to `kubeadm.k8s.io/v1beta4`.

**Linux note:** Docker on Linux does not resolve `host.docker.internal` automatically.
Add `--add-host=host.docker.internal:host-gateway` to your Docker daemon configuration
so that the agentgateway backend can reach LM Studio on the host. See the Docker docs
for your distribution.

---

## 4. Quick Start

```bash
git clone <repo>
cd falco-agentic-triage

# Step 1: Start LM Studio, load Gemma4, start the server on port 1234
# (detailed instructions in §5a below)

# Step 2: Copy the exact model identifier from LM Studio's server tab and
# paste it into BOTH of these files:
#   infra/agentgateway/llm-backend.yaml  →  spec.llm.model
#   infra/kagent/model-config.yaml       →  spec.model

# Step 3: Verify LM Studio is reachable
make check-lmstudio

# Step 4: Create cluster and install all components (~8–10 min)
make setup

# Step 5: Run the simple single-alert scenario
make scenario-a
make ui          # opens http://localhost:8080 — check the Raw Alerts tab

# Step 6: After the agent cycles (~30s), check the Triage Reports tab

# Step 7: Run the multi-alert correlation scenario
make clean-scenario
make scenario-b
# Watch the Triage Reports tab for a HIGH/ESCALATE correlation result
```

---

## 5. Detailed Installation Walkthrough

### Install kind

```bash
brew install kind         # macOS
# or download from https://kind.sigs.k8s.io/docs/user/quick-start/
kind version              # should print v0.32.0
```

### Install kubectl and helm

```bash
brew install kubectl helm
```

### Create the cluster

```bash
make cluster
```

This runs `kind create cluster --name falco-triage-demo --config kind-config.yaml`.
The cluster has:
- A single control-plane node (`kindest/node:v1.35.5`)
- Kubernetes Audit Log enabled (writes to `/var/log/kubernetes/audit.log`)
- Audit webhook configured to deliver events to Falco's k8saudit plugin on port 30765
- NodePort 30080 → host port 8080 (webhook-receiver UI)

Expected output:
```
Creating cluster "falco-triage-demo" ...
 ✓ Ensuring node image ...
 ✓ Preparing nodes ...
 ✓ Writing configuration ...
 ✓ Starting control-plane ...
 ✓ Installing CNI ...
 ✓ Installing StorageClass ...
Set kubectl context to "kind-falco-triage-demo"
```

### Install all infrastructure

```bash
make infra
```

This runs five steps in order:

**Step 1 — Falco Operator (Helm chart v0.2.0)**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/falco-operator
helm upgrade --install falco-operator falcosecurity/falco-operator \
  --namespace falco-operator --create-namespace --version 0.2.0 --wait
```

Then applies the Falco CRs:
```bash
kubectl apply -f infra/falco-operator/rulesfiles/
kubectl apply -f infra/falco-operator/plugin-container.yaml
kubectl apply -f infra/falco-operator/plugin-k8saudit.yaml
kubectl apply -f infra/falco-operator/falco-http-output-config.yaml
kubectl apply -f infra/falco-operator/falco-instance.yaml
kubectl apply -f infra/falco-operator/falcosidekick-component.yaml
```

Note: `falco-http-output-config.yaml` is a ConfigMap that enables JSON output and
HTTP forwarding via Falco's `config.d` drop-in mechanism. It must be applied before
`falco-instance.yaml` since the Falco pod mounts it at startup.

Validation:
```bash
kubectl get pods -n falco-operator
kubectl get pods -n falco
kubectl get falco -n falco
kubectl get component -n falco
```

**Step 2 — kube-prometheus-stack**

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace -f infra/prometheus/values.yaml --wait
```

Validation:
```bash
kubectl get pods -n monitoring
```

**Step 3 — agentgateway (v1.3.0)**

```bash
helm upgrade --install agentgateway oci://cr.agentgateway.dev/charts/agentgateway \
  --version 1.3.0 --namespace agentgateway-system --create-namespace --wait
kubectl apply -f infra/agentgateway/gateway.yaml
kubectl apply -f infra/agentgateway/llm-backend.yaml
```

Validation:
```bash
kubectl get pods -n agentgateway-system
kubectl get gateway -n agentgateway-system
```

**Step 4 — kagent (v0.9.10)**

```bash
helm upgrade --install kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
  --version 0.9.10 --namespace kagent --create-namespace --wait
helm upgrade --install kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent \
  --version 0.9.10 --namespace kagent --create-namespace \
  --set k8s-agent.enabled=false --set kgateway-agent.enabled=false --wait
kubectl apply -f infra/kagent/rbac.yaml
kubectl apply -f infra/kagent/model-config.yaml
kubectl apply -f infra/kagent/remotemcpserver-webhook.yaml
kubectl apply -f infra/kagent/triage-agent.yaml
```

The triage-agent uses two MCP server connections:
1. `webhook-receiver-mcp` (at `/mcp`) — `get_alert_buffer` and `post_triage_result`
2. `kagent-tool-server` (built-in kagent tools) — `k8s_get_resources` for pod metadata

Validation:
```bash
kubectl get pods -n kagent
kubectl get agent -n kagent
```

**Step 5 — webhook-receiver**

```bash
docker build -t webhook-receiver:latest webhook-receiver/
kind load docker-image webhook-receiver:latest --name falco-triage-demo
kubectl create namespace demo
kubectl apply -f webhook-receiver/k8s/
```

Validation:
```bash
kubectl get pods -n demo
curl -s http://localhost:8080/ | grep -i triage
```

### Full validation checklist

```bash
# All Falco components
kubectl get pods -n falco-operator
kubectl get pods -n falco
kubectl get falco -n falco
kubectl get component -n falco
kubectl get pods -n falco -l app.kubernetes.io/name=falcosidekick

# k8saudit plugin loaded
kubectl get plugin -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i k8saudit

# Prometheus
kubectl get pods -n monitoring

# agentgateway
kubectl get pods -n agentgateway-system
kubectl get gateway -n agentgateway-system

# kagent
kubectl get pods -n kagent
kubectl get agent -n kagent

# webhook-receiver UI
kubectl get pods -n demo
curl -s http://localhost:8080/ | grep -i triage

# LM Studio reachable from inside the cluster
kubectl run test-lmstudio --rm -i --restart=Never \
  --image=curlimages/curl:8.8.0 -- \
  curl -s http://host.docker.internal:1234/v1/models
```

---

## 5a. LM Studio Setup (Required Before `make setup`)

### What LM Studio is and why we use it

LM Studio is a desktop application that downloads open-weight LLM models and
serves them locally via an OpenAI-compatible HTTP API on `localhost:1234`. The
demo uses it to run Gemma4 entirely on your machine — no API keys, no cloud costs,
no data leaving the host. The triage agent inside the Kubernetes cluster talks to
LM Studio through agentgateway, which proxies requests from inside Kind to the Mac
host via `host.docker.internal:1234`.

### Step 1 — Download and install LM Studio

Go to https://lmstudio.ai/download. Download the macOS `.dmg` (choose Apple Silicon
or Intel to match your Mac). Open the dmg, drag LM Studio to Applications, and launch
it. Allow any network permission prompts on first launch.

### Step 2 — Download Gemma4

In LM Studio, press `Cmd+Shift+M` to open the model search. Search for `gemma-4`.
Choose a variant based on your hardware:

| Model | RAM required | Quality |
|-------|-------------|---------|
| `google/gemma-4-27b-it` | ≥32 GB | Best |
| `google/gemma-4-12b-it` | ≥16 GB | Good (recommended for demo) |
| `google/gemma-4-4b-it`  | ≥8 GB  | Sufficient for demo |

LM Studio suggests the best quantization for your hardware automatically. Click
Download and wait (model files are several GB).

### Step 3 — Load the model

After download, click the model in "My Models" to load it. Wait for the status bar
to show **Loaded**.

### Step 4 — Start the local server

Click the `<->` sidebar icon (or navigate to **Developer → Local Server**). Click
**Start Server**. The status changes to **Running** at `http://localhost:1234`.

Ensure **Enable CORS** is checked in the server settings — requests from inside the
Kind cluster come from a different origin.

### Step 5 — Note the exact model identifier

In the server tab, look at the **Model** dropdown. Copy the exact string shown,
for example:

```
google/gemma-4-12b-it-GGUF/gemma-4-12b-it-Q4_K_M.gguf
```

Paste this exact string into **both** of these files:
- `infra/agentgateway/llm-backend.yaml` → `spec.llm.model`
- `infra/kagent/model-config.yaml` → `spec.model`

A mismatch causes the agent to receive a 404 from agentgateway.

### Step 6 — Verify the server

```bash
# List models
curl http://localhost:1234/v1/models

# Quick smoke test (replace with your actual model identifier)
curl http://localhost:1234/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "google/gemma-4-12b-it-GGUF/gemma-4-12b-it-Q4_K_M.gguf",
    "messages": [{"role": "user", "content": "Reply with the word OK"}],
    "max_tokens": 10
  }'
```

Expected: a JSON response with `choices[0].message.content` containing "OK".

### Step 7 — Keep LM Studio running

LM Studio must stay open and the server must remain active throughout the demo.
You can minimize the window.

### Alternative: Ollama

Install Ollama from https://ollama.com, run `ollama pull gemma4`, start with
`ollama serve`. Default endpoint: `http://localhost:11434/v1`. Update both
`llm-backend.yaml` and `model-config.yaml` to use this base URL. Ollama runs
as a background service and does not require a GUI.

---

### Model selection guide for MacBook Pro M2

The demo works with Gemma4, but Gemma4 at 4B requires prompt engineering workarounds
to achieve reliable tool-calling (see §8 for details). If you have the RAM budget,
the models below are measurably more reliable for multi-step function-calling chains.

**Recommended alternatives by RAM tier:**

| RAM | Model | Ollama name | Tool-calling quality |
|-----|-------|-------------|----------------------|
| 8 GB | Qwen2.5-7B-Instruct | `qwen2.5:7b` | Good — significantly better than Gemma4 4B |
| 8 GB | Phi-4-mini (3.8B) | `phi4-mini` | Good for small footprint |
| 16 GB | Qwen2.5-14B-Instruct | `qwen2.5:14b` | Very good — recommended for this demo |
| 16 GB | Phi-4 (14B) | `phi4` | Very good reasoning, strong schema adherence |
| 16 GB | Gemma4 12B | `gemma4:12b` | Good — the prompt workarounds in this repo still apply |
| 32 GB | Qwen2.5-32B-Instruct | `qwen2.5:32b` | Excellent — reliable at 5+ tool chains without prompt hacks |
| 32 GB | Gemma4 27B | `gemma4:27b` | Excellent — context threshold moves to ~6 000 tokens |

M2 Pro has 16–32 GB; M2 Max 32–64 GB; M2 Ultra 64–192 GB.

**Why Qwen2.5 over Gemma4 at the same size?**
Qwen2.5 was trained with explicit emphasis on structured output and function-calling.
In practice, it rarely generates tool responses as free text, tolerates longer tool
chains without drifting, and uses consistent field names across runs. For this demo's
4-tool chain, Qwen2.5-7B is more reliable than Gemma4 12B despite being smaller.
The context-length threshold and session-accumulation workarounds described in §8
were developed specifically because Gemma4 was the chosen model; with Qwen2.5 or
Phi-4 those workarounds become less critical (though still harmless to keep in place).

**Switching models:**

With LM Studio: download the model, load it, copy the exact identifier from the
server tab, paste into `llm-backend.yaml` and `model-config.yaml`. Restart the
agentgateway backend or run `kubectl rollout restart deployment/triage-agent -n kagent`.

With Ollama:
```bash
ollama pull qwen2.5:14b
# Update llm-backend.yaml: spec.llm.baseURL → http://host.docker.internal:11434/v1
# Update model-config.yaml: spec.model → qwen2.5:14b
kubectl apply -f infra/agentgateway/llm-backend.yaml
kubectl apply -f infra/kagent/model-config.yaml
kubectl rollout restart deployment/triage-agent -n kagent
```

The model identifier for Ollama is always the short name (`qwen2.5:14b`, `phi4`,
etc.). For LM Studio it is the full GGUF path shown in the server tab.

---

## 6. Scenarios

### Scenario A: Shell in Container

**Run it:**
```bash
make scenario-a
```

**What happens:** The `event-generator` Job in namespace `prod` calls
`syscall.ExecInsideContainer`, spawning a shell inside a running container.
Falco fires the **Terminal shell in container** rule at WARNING priority.

**Alert flow:**
1. Falco emits the alert as JSON to Falcosidekick
2. Falcosidekick POSTs to `/ingest`; the receiver adds to both raw_alerts and alert_buffer (prod ns only)
3. After 30 seconds, the webhook-receiver triggers the agent via kagent A2A
4. Agent calls `get_alert_buffer` MCP tool, then `k8s_get_resources` for pod metadata
5. Agent calls `post_triage_result` MCP tool with the structured JSON report; buffer is flushed

**Typical triage output:**
```json
{
  "window_start": "2025-09-15T10:04:00Z",
  "window_end": "2025-09-15T10:04:30Z",
  "alert_count": 1,
  "affected_workloads": [
    {
      "pod": "event-generator-7d9f8b",
      "namespace": "prod",
      "image": "falcosecurity/event-generator:0.13.0",
      "alert_timeline": ["2025-09-15T10:04:03Z Terminal shell in container WARNING"]
    }
  ],
  "correlation_summary": "A single terminal shell event was detected in namespace prod. No corroborating signals (no sensitive file reads, no network anomalies, no /etc writes) were observed. The event may represent an authorized kubectl exec by an engineer.",
  "severity": "LOW",
  "confidence": 55,
  "evidence": [
    "Terminal shell in container fired on event-generator-7d9f8b at 10:04:03Z"
  ],
  "prometheus_anomalies": [],
  "recommended_action": "Confirm with the team whether a kubectl exec was authorized against prod at this timestamp. If unplanned, escalate to the on-call team.",
  "decision": "ESCALATE",
  "suppression_reason": null
}
```

The agent ESCALATEs because confidence (55) < 70, per the constraint in the system
prompt. This is the correct behavior for an isolated, ambiguous alert.

### Scenario B: Multi-Alert Attack Sequence

**Run it:**
```bash
make clean-scenario
make scenario-b
```

**What happens:** The `event-generator` Job runs three actions in sequence with
3-second gaps — all within one 30-second triage window:

| Time | Event | Rule | Priority |
|------|-------|------|----------|
| T+0s | Read `/etc/shadow` | Read sensitive file untrusted | WARNING |
| T+3s | Spawn shell | Terminal shell in container | WARNING |
| T+6s | Write to `/etc/` | Write below etc | ERROR |

**Typical triage output:**
```json
{
  "window_start": "2025-09-15T10:12:00Z",
  "window_end": "2025-09-15T10:12:09Z",
  "alert_count": 3,
  "affected_workloads": [
    {
      "pod": "event-generator-4f2a1c",
      "namespace": "prod",
      "image": "docker.io/falcosecurity/event-generator",
      "alert_timeline": [
        {"time": "2025-09-15T10:12:00Z", "type": "Warning"},
        {"time": "2025-09-15T10:12:03Z", "type": "Warning"},
        {"time": "2025-09-15T10:12:09Z", "type": "Error"}
      ],
      "alert_timeline_description": "Multi-stage attack sequence: read /etc/passwd (Warning) → read /etc/shadow (Warning) → write /etc/falco-demo-persistence-marker (Error)."
    }
  ],
  "correlation_summary": "The alerts indicate a multi-stage suspicious sequence originating from the event-generator container in the prod namespace. The process attempted to read /etc/passwd and /etc/shadow (credential reconnaissance), then wrote a file into the protected /etc directory using root privileges (persistence attempt). These actions form a clear attack pattern: reconnaissance → privilege escalation → persistence.",
  "severity": "HIGH",
  "confidence": 95,
  "evidence": [
    "Three successive alerts from event-generator-4f2a1c: read sensitive files followed by write to /etc",
    "Sequential timing (9 seconds total) is consistent with scripted attack actions",
    "Root-level write to /etc matches persistence attempt pattern"
  ],
  "prometheus_anomalies": [],
  "recommended_action": "Investigate the process execution path of the event-generator container for signs of compromise. Review runtime permissions and consider stricter Seccomp/AppArmor profiles. Engage the incident response team.",
  "decision": "ESCALATE",
  "suppression_reason": null
}
```

---

## 7. Why This Agent — Operator Value

### What the agent replaces

When a Falco alert fires without an agent, a SOC analyst must:

1. Get paged — possibly at 3am — with a raw JSON blob from Falcosidekick
2. Manually run `kubectl get pod`, `kubectl describe`, `kubectl get events`
3. Open Grafana and build PromQL queries for the right pod and timeframe
4. Recall what the alert rule means and whether it has fired before
5. Cross-reference with other alerts to see if a multi-step pattern is forming
6. Write up an incident summary and decide whether to wake the IR team

This takes **15–30 minutes per alert**, requires deep Kubernetes familiarity,
and degrades sharply with alert volume and analyst fatigue.

### What the agent does instead

Within 30–90 seconds of the alert window closing, the agent:

| Step | Tool | What it learns |
|------|------|----------------|
| Fetch alert batch | `get_alert_buffer` | Rule names, priorities, timestamps, pod/namespace |
| Pod metadata | `k8s_get_resources` | Image, labels, owner, service account, security context |
| Lifecycle events | `get_pod_events` | CrashLoops, OOMKills, restart count, scheduling failures |
| Resource metrics | `get_pod_metrics` | CPU/memory/network peaks during the alert window |
| Submit report | `post_triage_result` | Structured ESCALATE/SUPPRESS with narrative |

The analyst opens the UI and finds a pre-built report with a correlation
narrative, a severity badge, a confidence score, and a specific recommended
action. Their job becomes **validation**, not investigation.

### Data sources and coverage

| Source | How it reaches the agent | What it covers |
|--------|--------------------------|----------------|
| Falco syscall rules | `get_alert_buffer` | Runtime behaviour: file reads, shell spawns, network connections |
| Falco k8saudit rules | `get_alert_buffer` | K8s API actions: kubectl exec, secret reads, RBAC changes. The k8saudit plugin bridges the K8s audit log into Falco alerts — rules with "K8s" in their name come from this pipeline |
| K8s pod metadata | `k8s_get_resources` | Image provenance, labels, security context, owner chain |
| K8s lifecycle events | `get_pod_events` | OOMKills, restarts, scheduling failures — context for whether the pod was already unhealthy |
| Prometheus | `get_pod_metrics` | CPU/memory/network peaks correlated with the alert window |

**What is not covered:** Raw audit log queries (user identity, source IP, exact
API payload) would require a log aggregation pipeline (Loki, OpenSearch, Elastic).
The k8saudit plugin covers the detection side; deep forensic enrichment of the
caller identity is left to the IR team after escalation.

### Quantified savings (rough order of magnitude)

| Metric | Without agent | With agent |
|--------|--------------|------------|
| Time to first context | 15–30 min | 30–90 sec |
| Alerts correlated per incident | 1 (each triaged separately) | All alerts in a 30s window |
| Analyst skill required for initial triage | Senior (kubectl, PromQL, Falco rule knowledge) | Junior (review pre-built report) |
| False positive escalation rate | High (analyst unsure → escalates to be safe) | Lower (agent provides corroborating evidence for SUPPRESS) |
| Coverage at 3am | Depends on on-call quality | Consistent |

### What the agent deliberately does not do

- **No remediation.** The agent never deletes pods, changes network policies,
  rotates secrets, or calls any mutating K8s API. Every ESCALATE decision
  requires a human before any action is taken.
- **No detection.** Falco does the detection. The agent only triages what Falco
  already found.
- **No tuning.** The agent does not modify Falco rules or suppress future alerts.

---

## 8. Design Decisions and Production Alternatives

**Alert ingestion model:** The demo uses a polling model — the agent GETs `/buffer`
every 30 seconds. For production: (a) a message queue (Redis Streams, NATS, Kafka)
where Falcosidekick pushes and the agent consumes via a streaming interface; (b) a
gRPC streaming connection. The polling model is chosen here for simplicity and
auditability — every cycle is a discrete, logged event with a clear start and end.

**In-memory state:** The webhook-receiver uses Python `deque(maxlen=100)`. For
production: Redis (for multi-replica receiver), a time-series store (for alert
history and trend analysis), or a proper event log (Kafka, Kinesis).

**LLM provider:** LM Studio with Gemma4 enables fully local, offline operation.
For production: swap the `AgentgatewayBackend` to point at a managed endpoint
(Vertex AI, Bedrock, or self-hosted vLLM). Because the `ModelConfig` abstraction
sits between the agent and the provider, no agent code changes are required.

**LLM function-calling reliability — lessons from development:** The demo was built
and tested with Gemma4 running locally. Several non-obvious behaviors shaped the
final implementation.

*Context length is the main reliability lever.* At roughly 3 500 input tokens,
Gemma4 (all sizes, including 12B) switches from emitting tool calls to generating
the triage report as free text. The root cause is that the model has already
assembled a complete mental answer from the accumulated tool results and "forgets"
that it must submit that answer through a specific tool call. The fix applied here
was to remove the `k8s_get_resources` step from the tool chain: the raw Pod JSON
that kagent returns for that tool added approximately 1 200 tokens per cycle, which
pushed the total context past the threshold. Pod image, namespace, and name are
already present in the Falco alert payload, so the information is not lost.

*Session accumulation is a silent failure mode.* kagent re-uses the same A2A
`sessionId` across all triage cycles by default, so the conversation history grows
with every cycle. After 8–10 cycles the context reaches 4 000+ tokens from the
start of the session, and the model completely loses reliable function-calling
behaviour. The fix is one line in the trigger: generate a fresh `uuid4()` as the
`sessionId` for every A2A `message/send` call (see `_invoke_agent_sync` in
`webhook-receiver/main.py`). This keeps each triage cycle independent with a clean
context around 1 200 input tokens.

*Short system prompt beats long schema.* Earlier versions of the prompt embedded
the full triage JSON schema with field-by-field descriptions. With Gemma4, this
reliably caused the model to produce the JSON as plain text (it treated the schema
as a template to fill in rather than as a description of a tool to call). The
current prompt contains no schema at all — field descriptions live in the
`post_triage_result` tool description, which the model processes separately from
the task instruction.

*Tool arguments arrive as JSON strings.* Gemma4 follows the OpenAI function-calling
convention where `function.arguments` is a JSON-encoded string (e.g.,
`"{\"pod\":\"event-generator\"}"`) rather than a parsed object. The MCP
`tools/call` spec expects a JSON object in `arguments`, but ADK passes the raw
string. The webhook-receiver MCP handler detects this and parses the string before
processing (see the `isinstance(arguments, str)` guard in `/mcp`).

*Field naming is non-deterministic.* The same model, across different runs, uses
`pod`, `pod_name`, `k8s_pod_name`, or `name` for the pod name field; and
`namespace`, `namespace_name`, or `k8s.ns.name` for namespace. The
`_normalize_report` function in `main.py` maps all observed variants to canonical
fields so the UI always renders correctly regardless of which name the model chose.

If the agent fails to call `post_triage_result` in one cycle, the buffer stays
non-empty and the trigger fires again in approximately 30 seconds. The system
self-corrects without manual intervention.

**Agent triggering:** The 30-second fixed window is the core teaching point of
this Refcard. For production: threshold-based triggering (N alerts in M seconds),
severity-based fast-path (CRITICAL alert triggers immediate analysis bypassing the
window), or a sliding window with deduplication.

**Observability:** agentgateway emits OTel traces for every LLM call. This demo
does not configure a trace collector. For production: add `opentelemetry-collector`
and connect agentgateway's OTel exporter. Combined with kagent's OTel spans, you
get full call-chain visibility from the Falco alert to the triage report token.

**Least privilege:** The demo kagent ServiceAccount has broad cluster-read access
(see `infra/kagent/rbac.yaml`). For production: scope it to specific namespaces
and resources using namespace-scoped `Roles` instead of `ClusterRoles`.

**Falco Operator teardown order:** When uninstalling without `kind delete cluster`,
always delete artifact CRs first (Rulesfile, Plugin), then instance CRs (Falco,
Component), then the Helm release. Reversing this order orphans artifact finalizers.
`make teardown` uses `kind delete cluster` which bypasses this — acceptable for a demo.

---

## 9. Troubleshooting

**Falco pod in CrashLoopBackOff**
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco
```
`modern_ebpf` requires kernel ≥ 5.8. On Docker Desktop for Mac the kernel is 6.x
(fine). On Linux, check `uname -r`.

**k8saudit plugin not receiving events**
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i k8saudit
```
Verify the audit webhook URL in `infra/audit-webhook-config.yaml` points to
`http://localhost:30765/k8s-audit` and that the falco-k8saudit NodePort Service
exists: `kubectl get svc falco-k8saudit -n falco`.

**agentgateway cannot reach LM Studio**
```bash
kubectl run test-lmstudio --rm -i --restart=Never \
  --image=curlimages/curl:8.8.0 -- \
  curl -sv http://host.docker.internal:1234/v1/models
```
On Linux: add `--add-host=host.docker.internal:host-gateway` to Docker daemon config.
On Mac: verify Docker Desktop is running (it sets up `host.docker.internal` automatically).

**Agent produces no output**
```bash
make logs-agent
kubectl get agent triage-agent -n kagent -o yaml
```
Check that the ModelConfig `baseURL` matches the agentgateway service name:
`kubectl get svc -n agentgateway-system`. Verify the model identifier in
`model-config.yaml` matches the one in LM Studio's server tab exactly.

**Agent calls k8s_get_resources then stops without posting a report**
```bash
kubectl logs -n agentgateway-system -l app.kubernetes.io/name=agentgateway | grep output_tokens | tail -5
curl -s http://localhost:8080/history | python3 -c "import json,sys; d=json.load(sys.stdin); print('buffer:', d['buffer_count'])"
```
If the final LLM call shows `output_tokens=800+` but `buffer_count` stays non-zero,
the model generated the report as plain text rather than calling `post_triage_result`.
This is a known non-determinism in Gemma4 4EB's tool-calling. Wait ~3 minutes — the
trigger loop will fire again and a new cycle will succeed. If this happens repeatedly,
try a larger Gemma4 variant in LM Studio (12B or 27B gives much higher tool-call
reliability).

**Falcosidekick not forwarding to /ingest**
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick
kubectl get component falcosidekick -n falco -o yaml
```
Check the `config.webhooks` array in the Component CRD. Verify the
webhook-receiver pod is Running: `kubectl get pods -n demo`.

**Webhook-receiver not updating in real time**
Open the browser DevTools Network tab and confirm the `/events` SSE connection
is open and receiving `ping` events every 5 seconds. If not, the webhook-receiver
pod may have restarted — check `make logs-receiver`.

---

## 10. References

- Falco documentation: https://falco.org/docs/
- Falco Operator: https://github.com/falcosecurity/falco-operator
- Falcosidekick: https://github.com/falcosecurity/falcosidekick
- event-generator: https://github.com/falcosecurity/event-generator
- kagent: https://kagent.dev/
- agentgateway: https://agentgateway.dev/
- kind: https://kind.sigs.k8s.io/
- kube-prometheus-stack: https://github.com/prometheus-community/helm-charts
- DZone Refcard: *(link to be added after publication)*
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
- NIST SP 800-61 Computer Security Incident Handling Guide: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
