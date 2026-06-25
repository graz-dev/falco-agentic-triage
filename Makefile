.PHONY: prereqs cluster infra setup \
        scenario-a scenario-b clean-scenario teardown \
        logs-falco logs-agent logs-receiver ui check-lmstudio \
        _infra-falco-operator _infra-prometheus _infra-agentgateway \
        _infra-kagent _infra-webhook-receiver

CLUSTER_NAME   := falco-triage-demo
RECEIVER_IMAGE := webhook-receiver:latest
KIND_CONFIG    := kind-config.yaml

# ─── Prerequisites ─────────────────────────────────────────────────────────────

prereqs:
	@echo "=== Checking prerequisites ==="
	@command -v kind >/dev/null 2>&1 \
		|| { echo "ERROR: kind not found. Install: https://kind.sigs.k8s.io/docs/user/quick-start/"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 \
		|| { echo "ERROR: kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/"; exit 1; }
	@command -v helm >/dev/null 2>&1 \
		|| { echo "ERROR: helm not found. Install: https://helm.sh/docs/intro/install/"; exit 1; }
	@command -v docker >/dev/null 2>&1 \
		|| { echo "ERROR: docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1; }
	@echo "Checking LM Studio on localhost:1234 ..."
	@curl -sf --max-time 5 http://localhost:1234/v1/models >/dev/null \
		|| { echo "ERROR: LM Studio not reachable on localhost:1234. Start LM Studio, load Gemma4, and enable the server (Developer → Local Server → Start)."; exit 1; }
	@echo "All prerequisites satisfied."
	@uname -s | grep -q Linux \
		&& echo "LINUX NOTE: Kind node images do not add host.docker.internal automatically." \
		&& echo "            Add '--add-host=host.docker.internal:host-gateway' to your Docker daemon config" \
		&& echo "            or the LLM backend in agentgateway will fail to reach LM Studio." \
		|| true

# ─── Cluster ───────────────────────────────────────────────────────────────────

cluster:
	@echo "=== Creating Kind cluster: $(CLUSTER_NAME) ==="
	@kind get clusters 2>/dev/null | grep -q "^$(CLUSTER_NAME)$$" \
		&& echo "Cluster '$(CLUSTER_NAME)' already exists — skipping creation." \
		|| kind create cluster --name $(CLUSTER_NAME) --config $(KIND_CONFIG)
	@kubectl wait --for=condition=Ready node --all --timeout=120s
	@echo "Cluster ready."

# ─── Infrastructure (idempotent — safe to run twice) ──────────────────────────

infra: _infra-falco-operator _infra-prometheus _infra-agentgateway _infra-kagent _infra-webhook-receiver
	@echo ""
	@echo "=== All infrastructure components deployed ==="
	@echo "Run 'make ui' to open the webhook-receiver UI at http://localhost:8080"

_infra-falco-operator:
	@echo ""
	@echo "--- [1/5] Falco Operator ---"
	@helm repo add falcosecurity-charts https://falcosecurity.github.io/charts 2>/dev/null || true
	@helm repo update falcosecurity-charts
	@helm upgrade --install falco-operator falcosecurity-charts/falco-operator \
		--namespace falco-operator --create-namespace \
		--version 0.2.0 \
		--wait --timeout 5m
	@kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f -
	@kubectl apply -f infra/falco-operator/rulesfiles/rulesfile-default.yaml
	@kubectl apply -f infra/falco-operator/rulesfiles/rulesfile-scenario-b.yaml
	@kubectl apply -f infra/falco-operator/plugin-container.yaml
	@kubectl apply -f infra/falco-operator/plugin-k8saudit.yaml
	@kubectl apply -f infra/falco-operator/falco-http-output-config.yaml
	@kubectl apply -f infra/falco-operator/falco-instance.yaml
	@kubectl apply -f infra/falco-operator/falcosidekick-component.yaml
	@echo "Waiting for Falco pods to be Ready ..."
	@kubectl wait --for=condition=Ready pods -n falco --all --timeout=5m \
		|| (echo "WARNING: Some Falco pods may still be starting; check 'make logs-falco'"; true)

_infra-prometheus:
	@echo ""
	@echo "--- [2/5] kube-prometheus-stack ---"
	@helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
	@helm repo update prometheus-community
	@helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
		--namespace monitoring --create-namespace \
		-f infra/prometheus/values.yaml \
		--wait --timeout 10m

_infra-agentgateway:
	@echo ""
	@echo "--- [3/5] agentgateway ---"
	@echo "Installing Kubernetes Gateway API CRDs ..."
	@kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
	@echo "Installing agentgateway CRDs chart ..."
	@helm upgrade --install agentgateway-crds \
		oci://cr.agentgateway.dev/charts/agentgateway-crds \
		--version 1.3.0 \
		--namespace agentgateway-system --create-namespace \
		--wait --timeout 2m
	@echo "Installing agentgateway controller ..."
	@helm upgrade --install agentgateway \
		oci://cr.agentgateway.dev/charts/agentgateway \
		--version 1.3.0 \
		--namespace agentgateway-system --create-namespace \
		--wait --timeout 5m
	@kubectl apply -f infra/agentgateway/gateway.yaml
	@kubectl apply -f infra/agentgateway/llm-backend.yaml
	@echo "Waiting for agentgateway pods ..."
	@kubectl wait --for=condition=Ready pods -n agentgateway-system --all --timeout=3m

_infra-kagent:
	@echo ""
	@echo "--- [4/5] kagent ---"
	@echo "Installing kagent CRDs ..."
	@helm upgrade --install kagent-crds \
		oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
		--version 0.9.10 \
		--namespace kagent --create-namespace \
		--wait --timeout 2m
	@echo "Installing kagent controller (bundled agents disabled) ..."
	@helm upgrade --install kagent \
		oci://ghcr.io/kagent-dev/kagent/helm/kagent \
		--version 0.9.10 \
		--namespace kagent --create-namespace \
		--set k8s-agent.enabled=false \
		--set kgateway-agent.enabled=false \
		--set istio-agent.enabled=false \
		--set promql-agent.enabled=false \
		--set observability-agent.enabled=false \
		--set argo-rollouts-agent.enabled=false \
		--set helm-agent.enabled=false \
		--set cilium-policy-agent.enabled=false \
		--set cilium-manager-agent.enabled=false \
		--set cilium-debug-agent.enabled=false \
		--set grafana-mcp.enabled=false \
		--set kmcp.enabled=false \
		--set substrate.enabled=false \
		--timeout 5m
	@echo "Waiting for kagent pods (controller may need PostgreSQL to be ready) ..."
	@kubectl wait --for=condition=Ready pod -n kagent -l app.kubernetes.io/component=controller --timeout=5m
	@kubectl apply -f infra/kagent/rbac.yaml
	@kubectl apply -f infra/kagent/model-config.yaml
	@kubectl apply -f infra/kagent/remotemcpserver-webhook.yaml
	@kubectl apply -f infra/kagent/triage-agent.yaml

_infra-webhook-receiver:
	@echo ""
	@echo "--- [5/5] webhook-receiver ---"
	@docker build --provenance=false --sbom=false -t $(RECEIVER_IMAGE) webhook-receiver/
	@docker save $(RECEIVER_IMAGE) | docker exec -i $(CLUSTER_NAME)-control-plane \
		ctr --namespace=k8s.io images import -
	@kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -
	@kubectl apply -f webhook-receiver/k8s/deployment.yaml
	@kubectl apply -f webhook-receiver/k8s/service.yaml
	@kubectl rollout status deployment/webhook-receiver -n demo --timeout=2m

# ─── Combined setup ────────────────────────────────────────────────────────────

setup: cluster infra

# ─── Scenarios ─────────────────────────────────────────────────────────────────

scenario-a:
	@echo "=== Scenario A: Shell in container ==="
	@kubectl apply -f scenarios/target-workload.yaml
	@kubectl wait --for=condition=Available deployment/webapp -n prod --timeout=2m
	@kubectl delete job event-generator -n prod --ignore-not-found
	@kubectl apply -f scenarios/scenario-a/event-generator.yaml
	@echo "Event generator started. Watch the UI at http://localhost:8080"
	@echo "Tailing webhook-receiver logs (Ctrl+C to stop) ..."
	@kubectl logs -n demo -l app=webhook-receiver --tail=0 -f

scenario-b:
	@echo "=== Scenario B: Multi-alert attack sequence ==="
	@kubectl apply -f scenarios/target-workload.yaml
	@kubectl wait --for=condition=Available deployment/webapp -n prod --timeout=2m
	@kubectl delete job event-generator -n prod --ignore-not-found
	@kubectl apply -f scenarios/scenario-b/event-generator.yaml
	@echo "Three-stage attack sequence started (9 seconds total)."
	@echo "Watch the Triage Reports tab at http://localhost:8080 — report appears within 30s."
	@echo "Tailing webhook-receiver logs (Ctrl+C to stop) ..."
	@kubectl logs -n demo -l app=webhook-receiver --tail=0 -f

clean-scenario:
	@echo "=== Cleaning up scenario resources ==="
	@kubectl delete job event-generator -n prod --ignore-not-found
	@kubectl delete deployment webapp -n prod --ignore-not-found
	@kubectl delete serviceaccount event-generator -n prod --ignore-not-found
	@kubectl delete role event-generator -n prod --ignore-not-found
	@kubectl delete rolebinding event-generator -n prod --ignore-not-found

# ─── Teardown ──────────────────────────────────────────────────────────────────

teardown:
	@echo "=== Deleting Kind cluster: $(CLUSTER_NAME) ==="
	@kind delete cluster --name $(CLUSTER_NAME)

# ─── Observability shortcuts ───────────────────────────────────────────────────

logs-falco:
	kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 -f

logs-agent:
	kubectl logs -n kagent -l app=triage-agent --tail=50 -f

logs-receiver:
	kubectl logs -n demo -l app=webhook-receiver --tail=50 -f

# ─── UI & checks ───────────────────────────────────────────────────────────────

ui:
	@open http://localhost:8080 2>/dev/null || xdg-open http://localhost:8080 2>/dev/null \
		|| echo "Open http://localhost:8080 in your browser"

check-lmstudio:
	curl -s http://localhost:1234/v1/models | python3 -m json.tool
