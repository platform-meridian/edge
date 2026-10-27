# deploy

A kustomize base whose deployment values are placeholders. Before applying it,
substitute:

| Placeholder | Value |
|---|---|
| `@OPERATOR_DOMAIN@` | the domain operators reach the device on |
| `@OPERATOR_ADDR@` | the address operators reach the device at |
| `@APISERVER_HOST@`, `@APISERVER_PORT@` | the node's kube-apiserver |
| `@CLUSTER_DNS@` | the kubelet's `clusterDNS` address |
| `@BUILD_EPOCH@` | the build time, the earliest the clock may read (edge-scope) |

The images are the published `ghcr.io/platform-meridian/edge-<name>`, tagged in
`kustomization.yaml`; override those names to pin digests.

Then provide:

- the Gateway API CRDs;
- optionally, the CA edge-signer signs with: Secret `edge-signer-ca` in `edge`,
  type `kubernetes.io/tls`, `tls.key` its PKCS#8 P-256 key and `tls.crt` the
  chain from the issuing CA up to the root. Without it the signer creates the
  device's own, constrained to the names above and loopback;
- Talos API access with `os:admin` for namespace `edge`
  (`KubeTalosAPIAccessConfig`): edge-update applies updates with it, and
  edge-signer issues operators access with it. A caller of edge-signer's access
  API on loopback presents its service account token and needs verb `issue` on
  `signers` named `edge.meridian/access`;
- for edge-update: the `edge-registry` user volume, a
  PersistentVolume of at least 16Gi for claim `edge/edge-update-state` (class
  `""`, e.g. a local PV on a user volume), and ConfigMap `edge-update` in
  `edge` holding Sigstore's `trusted_root.json` and a `config.yaml` naming
  who may sign, the node's store and the stack:

  ```yaml
  trustedRoot: /etc/edge-update/trusted_root.json
  trustPolicy:
    signers:                          # whose bundles the unit takes
      - issuer: https://token.actions.githubusercontent.com
        workflow: https://github.com/my-org/my-app/.github/workflows/release.yml
        ref: refs/tags/*
    allowUnsigned: false              # true for development only
  store: /var/lib/etcd/state.log      # copied off before each update
  bless: /var/mnt/my-volume/blessed   # boot-commit's record of the boot it blessed
  stack:
    url: oci://127.0.0.1:5000/my-stack  # the stack artifact's repository on the unit
    fluxInstance: flux-system/flux
    kustomization: flux-system/my-stack
    source: flux-system/my-stack        # the OCIRepository
    lock: flux-system/my-stack-lock     # built_epoch, and what LOCK_* lines check
    judge: flux-system/my-stack-commit  # good, previous, trial, rolled_back
    modules: flux-system/my-modules     # optional: the installed modules, written into each stack
  bootSigning:                        # optional: the unit signs each new OS's boot files
    dir: /var/mnt/boot-signing        # mounted at the same path; the host's boot signs what is staged here
    uki: /usr/install/amd64/vmlinuz.efi       # in the installer image
    bootloader: /usr/install/amd64/systemd-boot.efi
  ```

  With `bootSigning`, a new OS costs one more reboot: edge-update stages the
  verified release in `dir/staged/` and reboots, the host's early boot verifies
  and signs it while the unit's boot keys unseal (`signed/`, or why not in
  `refused`), and the installer is installed with the signed files over it. The
  host marks `dir/keys` on a unit with keys; without it the OS installs as built.
- nothing for app storage: edge-update's provisioner serves the default
  StorageClass `edge-local` (`edge-update.yaml`), each claim a Talos user
  volume of its own; and edge-update labels the node with the host's
  capabilities (`capability.platform.meridian/<name>`);
- any static routes, as ConfigMaps labelled `edge.meridian/routes`, in any
  namespace, each with its routes under `routes.yaml`. edge-gateway finds and
  follows them: an app ships its own and patches nothing of edge's. They are
  served after the config file's on a tie, in namespace/name order, and hold
  routes alone (no `authz_backend`, which is the config file's):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-routes
  namespace: my-app
  labels: { edge.meridian/routes: "true" }
data:
  routes.yaml: |
    routes:
      - { hostname: "mine.@OPERATOR_DOMAIN@", prefix: "/", authz: skip, backend: { host: "127.0.0.1", port: 3000 } }
```

`talos/` holds the Talos extension services: edge-scope, edge-layers,
edge-watch, edge-registry, edge-dhcp (`operator-lan`) and a minimal edge-cni
config that lets the node become Ready. edge-registry wants a user volume named
`edge-registry` and the machine's registry mirrors pointed at it. CI tags each
image with its commit, so one commit pins both manifests and images.
