# edge-pack

Packs an app's `deploy/` and images into the bundle `edge-update` installs: a
bundle without a base bringing one module (`edge-bundle`). The release
workflow is `.github/actions/app-release`.

## deploy/

`module.toml`, a kustomize tree, and the machine-config parts it names:

```toml
name = "web"                       # the module, its Kustomization and Secret
machine = ["machine.yaml"]         # merged into the unit's machine config
values = ["HUB"]                   # per-unit values, set at install

[requires]                         # minimums, checked on the unit
talos = ">=v1.14.0"
kubernetes = ">=v1.35.0"
components = ["helm-controller"]   # Flux controllers its objects need

[images]                           # pinned by digest; CI overrides with --image
WEB_IMAGE = "ghcr.io/my-org/app-web:v1.2.0@sha256:…"

[image_names]                      # the name the manifests use, which kustomize pins
WEB_IMAGE = "app-web"

[secrets]                          # generated on the unit by the secret owner
WEB_KEY = "hex32"
```

The manifests name what differs per unit as `${KEY}`, filled by Flux on the
unit: a node fact (`OPERATOR_ADDR`, `OPERATOR_DOMAIN`, `CLUSTER_DNS`,
`APISERVER_HOST`, `APISERVER_PORT`, from ConfigMap `flux-system/node-facts`),
a declared value (ConfigMap `flux-system/module-<name>-values`) or a declared
secret (Secret `flux-system/module-<name>`). Any other `${KEY}`, an unused
declaration, or a build-time `@KEY@` is refused.

Declared secrets need `--secret-owner <namespace>/<serviceaccount>` and
`--secret-label <key>=<value>`: the module carries a ConfigMap declaring the
Secret in that namespace with that label, and a Role letting that
ServiceAccount create it.

## Packing

```sh
edge-pack pack deploy staged --version v1.2.0 --epoch "$(git log -1 --format=%ct)" \
  --artifact ghcr.io/my-org/app-web/module --layout layout \
  --image WEB_IMAGE=ghcr.io/my-org/app-web:v1.2.0@sha256:…
cosign sign-blob --yes --new-bundle-format --bundle sig.json staged/SHA256SUMS
edge-pack seal staged sig.json app-web-v1.2.0.tar
oras push ghcr.io/my-org/app-web/app:v1.2.0 \
  --artifact-type application/vnd.meridian.app.v1 \
  app-web-v1.2.0.tar:application/vnd.meridian.bundle.v1.tar
```

`--layout` is an OCI image layout holding every image by digest
(`skopeo copy --all`). The same inputs pack the same sums.
