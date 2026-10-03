<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/meridian-edge-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/meridian-edge-light.svg">
  <img alt="Meridian Edge" src=".github/assets/meridian-edge-light.svg" height="80">
</picture>

---

Meridian Edge is the infrastructure for single-node Kubernetes on Talos Linux:
etcd, CNI, DNS, ingress, certificates and a watchdog, rewritten in Rust. It is
built for devices that run offline, lose power without warning, and must
recover without anyone on site.

| Component | |
|---|---|
| [`edge-state`](crates/edge-state/) | Replaces etcd: an append-only store for kube-apiserver that loses no acknowledged write on power loss. |
| [`edge-cni`](crates/edge-cni/) | Replaces flannel and kube-proxy: pod networking, Services, NetworkPolicy and NAT, in BPF and nftables. |
| [`edge-dns`](crates/edge-dns/) | Replaces CoreDNS: serves `cluster.local` and forwards everything else. |
| [`edge-dhcp`](crates/edge-dhcp/) | Replaces dnsmasq: DHCP and a local DNS name for the device on its operator port. |
| [`edge-gateway`](crates/edge-gateway/) | A Gateway API ingress on the host's own ports that authorises every request unless its route opts out. |
| [`edge-signer`](crates/edge-signer/) | Replaces cert-manager: signs Kubernetes pod certificates from the operator's CA, and approves the kubelets' serving certificates. |
| [`edge-update`](crates/edge-update/) | Verifies and applies signed update bundles: the OS on trial, then the stack, each committed or rolled back. |
| [`edge-watch`](crates/edge-watch/) | Keeps the hardware watchdog armed and resets the device when its health checks fail. |
| [`edge-scope`](crates/edge-scope/) | Records logs and hardware health so they survive resets and power loss. |
| [`edge-registry`](crates/edge-registry/) | An image registry that containerd and Flux pull through, with a store that survives power loss. |
| [`edge-layers`](crates/edge-layers/) | Repairs container image layers damaged by power loss before the kubelet starts. |
| [`edge-idle`](crates/edge-idle/) | Throttles the scheduler and controller-manager while the cluster is idle. |
| [`edge-kube`](crates/edge-kube/) | Library: the Service, EndpointSlice and NetworkPolicy view shared by edge-cni and edge-dns. |
| [`edge-bundle`](crates/edge-bundle/) | Library: the signed update bundle and machine-config patch formats, read by edge-update and written by build tooling. |
| [`edge-common`](crates/edge-common/) | Library: shutdown, logging, durable writes and sandboxing. |
| [`conformance/`](conformance/) | Release tests: kube-apiserver's storage tests and etcd's robustness tests against edge-state. |
| [`replay/`](replay/) | Records apiserver sessions and replays them against edge-state and etcd to compare the answers. |
| [`deploy/`](deploy/) | Kustomize manifests and Talos extension service specs, and what to substitute before applying them. |
