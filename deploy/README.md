# deploy

A kustomize base whose deployment values are placeholders. Before applying it,
substitute:

| Placeholder | Value |
|---|---|
| `@OPERATOR_DOMAIN@`, `@OPERATOR_ADDR@` | the domain and address operators reach the device on |
| `@NODE_HOSTNAME@` | the node's hostname |
| `@APISERVER_HOST@`, `@APISERVER_PORT@` | the node's kube-apiserver |
| `@CLUSTER_DNS@` | the kubelet's `clusterDNS` address |
| `@BUILD_EPOCH@` | the build time, the earliest the clock may read (edge-scope) |

Then provide:

- the images, named `edge-<name>:appliance`, through an `images:` transformer;
- the Gateway API CRDs;
- the CA edge-signer signs with, at `/etc/edge-signer/ca.pem` on the host;
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
