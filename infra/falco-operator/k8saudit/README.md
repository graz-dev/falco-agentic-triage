# k8saudit detection (Kubernetes audit log → Falco)

Adds a second detection source alongside the syscall DaemonSet: the Kubernetes **audit log**
(kubectl exec, secret reads, privileged pod creation, RBAC changes, …).

**Status:** detection path validated live on 2026-06-30 on a fresh single-node kind cluster
(Falco Operator 0.4.0 / Falco 0.44.1). Real alerts observed: `K8s Secret Get Successfully`,
`Attach/Exec Pod`, `Create Disallowed Namespace`.

## What this applies (`k8saudit-stack.yaml`)
- A dedicated **Deployment-mode** Falco (`falco-k8saudit` ns) — one stable endpoint for the
  audit webhook (a DaemonSet would expose one endpoint per node).
- Plugins **json** `0.7.4` + **k8saudit** `0.18.0` (the container plugin is NOT loaded here — it
  binds only to the syscall source and is inert on a plugins-only Deployment).
- Rulesfile **k8saudit ruleset** `0.18.0` (under `plugins/ruleset/`, not `falcosecurity/rules`).
- A `NodePort` Service (`falco-k8saudit-webhook`, nodePort **30765**) so the hostNetwork
  apiserver can deliver audit events to the plugin at `localhost:30765`.

The operator loads every Plugin/Rulesfile CR in the instance's namespace into that instance,
which is why these live in their own namespace (kept out of the syscall DaemonSet).

## Apiserver wiring (provided by the fresh single-node kind cluster)
The kube-apiserver must send audit events to Falco. On a fresh **single-node** kind cluster
this is wired at creation via `../../../kind-config.yaml`:
- `kubeadmConfigPatches`: add `--audit-policy-file`, `--audit-webhook-config-file`, and
  `--audit-webhook-initial-backoff=5s` to the apiserver.
- `extraMounts`: mount `infra/audit-policy.yaml` and `infra/audit-webhook-config.yaml` into the
  control-plane node.

The webhook target in `infra/audit-webhook-config.yaml` is `http://localhost:30765/k8s-audit`.
The apiserver runs with hostNetwork, so on a single-node cluster it reaches the k8saudit
plugin through the NodePort on the node's localhost. Audit-webhook deliveries that happen
before Falco is up are dropped silently (async batch mode), which is why the bootstrap order
brings Falco up early.

> Existing-cluster note: to retrofit audit onto an already-running cluster you must edit the
> apiserver static-pod manifest in the node and restart the container with `crictl rm`
> (deleting the mirror pod does NOT restart it). Prefer a fresh cluster.

## Trigger / verify
```
kubectl -n prod get secret demo-secret -o yaml        # -> K8s Secret Get Successfully (Error)
kubectl -n prod exec <pod> -- sh -c 'cat /etc/shadow' # -> Attach/Exec Pod (Notice) + syscall rule
kubectl logs -n falco-k8saudit deploy/falco-k8saudit -c falco | grep -E '^[0-9]{2}:'
```
