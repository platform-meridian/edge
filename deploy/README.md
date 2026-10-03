# deploy

A kustomize base whose deployment values are placeholders. Before applying it,
substitute:

| Placeholder | Value |
|---|---|
| `@OPERATOR_DOMAIN@`, `@OPERATOR_ADDR@` | the domain and address operators reach the device on |
| `@APISERVER_HOST@`, `@APISERVER_PORT@` | the node's kube-apiserver |
| `@CLUSTER_DNS@` | the kubelet's `clusterDNS` address |
| `@BUILD_EPOCH@` | the build time, the earliest the clock may read (edge-scope) |

The images are the published `ghcr.io/platform-meridian/edge-<name>`, tagged in
`kustomization.yaml`; override those names to pin digests.

Then provide:

- the Gateway API CRDs;
- the CA edge-signer signs with, at `/etc/edge-signer/ca.pem` on the host;
- for edge-update: Talos API access with `os:admin` for namespace `edge`
  (`KubeTalosAPIAccessConfig`), the `edge-update` and `edge-registry` user
  volumes, and ConfigMap `edge-update` in `edge` whose `config.yaml` names the
  key, the node's store and the stack:

  ```yaml
  signingKey: ssh-ed25519 AAAA...     # signs every bundle
  signatureNamespace: my-update       # ssh-keygen -Y sign -n
  store: /var/lib/etcd/state.log      # copied off before each update
  stack:
    url: oci://127.0.0.1:5000/my-stack  # the stack artifact's repository on the unit
    fluxInstance: flux-system/flux
    kustomization: flux-system/my-stack
    source: flux-system/my-stack        # the OCIRepository
    lock: flux-system/my-stack-lock     # built_epoch, and what LOCK_* lines check
    judge: flux-system/my-stack-commit  # good, previous, trial, rolled_back
  ```
- any static routes, as ConfigMaps projected into edge-gateway's
  `routes.d/`, merged in name order:

```yaml
patches:
  - target: { kind: Deployment, name: edge-gateway }
    patch: |-
      - op: add
        path: /spec/template/spec/volumes/0/projected/sources/-
        value:
          configMap:
            name: my-routes
            items: [{ key: routes.yaml, path: routes.d/10-mine.yaml }]
```

`talos/` holds the Talos extension services: edge-scope, edge-layers,
edge-watch, edge-registry, edge-dhcp (`operator-lan`) and a minimal edge-cni
config that lets the node become Ready. edge-registry wants a user volume named
`edge-registry` and the machine's registry mirrors pointed at it. CI tags each
image with its commit, so one commit pins both manifests and images.
