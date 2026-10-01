# edge-cni

Pod networking, Services, NetworkPolicy and NAT, in BPF and nftables.

## Differences from kube-proxy

`sessionAffinity: ClientIP` from outside the node (NodePorts) hashes the
client's address over the Service's backends rather than remembering each
client's backend:

- there is no timeout: `timeoutSeconds` applies only to clients on the node;
- a client may move to another backend when the backend set changes.
