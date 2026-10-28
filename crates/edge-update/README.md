# edge-update

Verifies signed bundles (`edge-bundle`), each the unit's base (its OS and
stack), and applies them to the unit it runs on, through the node's Talos API
and the cluster's Flux. Apps are `MeridianApp`s, which the platform controller
installs (ADR-0015); a bundle brings none. The API is
`proto/edge/update/v1/update.proto`; a console reaches it through whatever
fronts the unit.

## Trust

A bundle is signed keyless (`cosign sign-blob --bundle` over its
`SHA256SUMS`). The unit verifies offline against Sigstore's
`trusted_root.json` and takes only a signer its policy names:

```yaml
trustedRoot: /etc/edge-update/trusted_root.json
trustPolicy:
  signers:
    - issuer: https://token.actions.githubusercontent.com
      workflow: https://github.com/my-org/my-app/.github/workflows/release.yml
      ref: refs/tags/*    # exact, or a prefix ending in *
  allowUnsigned: false    # true takes a bundle without a signature: development only
```

The release names its signer, `<workflow>@<ref>`, or `unsigned`. An unsigned
bundle's files are still checked against its `SHA256SUMS`.

## An update, step by step

The status lists the update's steps in order, those still to come included,
each with its state and times. Only the steps the release needs are listed:
a release whose OS the unit already runs has no install, reboot or OS trial.

| Step | What happens |
|---|---|
| upload | chunks arrive, in any order; a dropped connection or a reload resumes |
| verify | the signature, then every file against the signed sums; the installed set composed; the unit's checks |
| stage | images imported, the state store copied off, the machine config staged |
| install | the new OS written beside the running one |
| reboot | into the new OS, on trial |
| os trial | until the unit commits the OS |
| stack | the judge updated, then the stack pointed at the new release |
| trial | until the judge commits or rolls the stack back |
| commit | images no kept release names collected |

The bundle's signed head (`SHA256SUMS`, its Sigstore bundle, `MANIFEST` and
`NOTES.md`) is read as soon as the start of the upload has arrived: a bundle
signed by a signer the policy does not name, or whose `MANIFEST` this engine
cannot take, is refused before the rest is sent.

One update at a time: `BeginUpload` and `Apply` take a `by`, an opaque name
for other clients. Another's upload of a different bundle is not replaced
until it has been idle for two minutes; the status's `lock` says who holds
the unit.

## Installed sets

Every bundle says in `components.json` (see `edge-bundle`) the base's refs and
nothing else: one that brings modules, or removes one, is refused. A unit
that installed modules before apps were `MeridianApp`s still runs them from
its stack until the appliance's switch-over (ADR-0015, phase 5), so
edge-update keeps the unit's *installed set*: the base and those modules. A
base update replaces the base and carries every module as it is: its Flux
objects, its MANIFEST lines and its machine-config parts. It composes the
stack for the result, the base's artifact with `modules/` rewritten, tags it
with a release id it mints in the repository the base's stack came from, and
keeps the set beside that tag. The release's MANIFEST, refs and machine
config are then the set's, so the judge, rollback and collection cover the
whole set: rolling back returns to the previous one. `Apply` takes the id.

`modules/` is a kustomize Component, which the stack includes under
`components:`. It holds one file of Flux objects per module and, with
`stack.modules` set, a ConfigMap of `MODULES` and each module's MANIFEST
lines. A base applied after the stack moved from the one it was verified on
is refused, as is one onto a unit whose set is unrecorded while its stack
says it runs modules.

Anti-rollback is the base's: one older than the installed `BUILT_EPOCH` is
refused. Each carried module's `requires` (Talos, Kubernetes, Flux
components) are checked at verify and again at apply.

## What runs, and what a release changes

`Unit.components` lists what runs: the images of the release the unit runs,
if this engine applied it, else the images its workloads name. `Unit.modules`
lists the modules installed: the running release's, else as `stack.modules`
records them. On
verification, `Release.diff` compares that with the release, image by image
(an image is its repository without registry, tag or digest), and says
whether the OS changes and so the unit reboots, whether the machine config
changes, and the expected downtime: the unit's last reboot through an update.

A bundle names the images a person tracks by `COMPONENT_<NAME>` lines in its
`MANIFEST` (see `edge-bundle`); their version is what the build calls them.

## The judge

The stack's judge is the consumer's. edge-update reads its record from the
ConfigMap `stack.judge` names, and knows nothing else of it. Required:

| Key | |
|---|---|
| `good` | the last release that stayed healthy |
| `previous` | the good release before it |
| `trial` | the release being judged, when it is not `good` |
| `rolled_back` | `<tag> <RFC 3339 time>` of the last rollback |

Optional, for a person following a trial:

| Key | |
|---|---|
| `commit_after_secs` | continuous health wanted before a commit |
| `fail_after_secs` | unhealthy time allowed before a rollback |
| `unhealthy_secs` | unhealthy time so far |
| `healthy_since` | RFC 3339 UTC start of the current healthy streak; empty while unhealthy |
| `checks` | a line per check: `pass <name>` or `fail <name>: <detail>` |
| `requests` | the requests it honours: `commit`, `rollback`, space-separated |

Requests: edge-update merges `request: commit <tag>` or `request: rollback
<tag>` into the ConfigMap. A judge that lists the request in `requests`
commits or rolls back `<tag>` on its next look if it is the release on trial,
and empties `request` either way. A judge that lists no `rollback` is not
asked: edge-update points the stack back at the release before the update
itself.

With nothing on trial, `RollBack` points the stack at the judge's `previous`
release, which the judge then takes on trial like any other. The OS stays.

A stack trial with no `good` release has nothing to roll back to, so one that
never comes up healthy would hold the unit until someone commits it. While
the judge's checks fail on such a trial, an upload and `Install` are taken
anyway: the trial is ended as failed, with the reason in the history, and
`Apply` moves the stack off it without waiting for a good release. A healthy
trial, or one with a release to roll back to, is never taken over.

## Storage

`GetStorage` says what the image store holds, what only the previous release
holds (kept so a rollback can return to it), and what nothing kept names.
`CollectGarbage` drops the latter, and the previous release's images too if
asked, after which a rollback to it is refused: it has no images to run.

## Volumes

An app asks for a PersistentVolumeClaim and never carries machine config.
edge-update is a Kubernetes external provisioner for StorageClasses whose
`provisioner` is `edge.meridian/local` (`deploy/edge-update.yaml` ships
`edge-local`, the default): a claim of one, on this node, becomes a Talos user
volume of its own, `pv-<24 hex>` from the claim's uid, ext4 on the system disk
and keyed as the unit's other user volumes, its size the request rounded up to
MiB. Once Talos says it is ready, the provisioner creates a `local`
PersistentVolume on `/var/mnt/<volume>`, on this node, bound to the claim.

Not a CSI driver: Talos partitions, keys, formats and mounts the volume, so a
node plugin would have nothing to do.

The engine is the machine config's one writer: the provisioner asks it to add
or remove a volume, and it does so only while idle with nothing staged for the
next boot, so a claim waits out an update. Every new config the engine merges
keeps the provisioned volumes whole (`edge-bundle`'s `machineconfig`).

Raw block claims, any access mode but `ReadWriteOnce` or `ReadWriteOncePod`, a
data source, a selector, or a resize are refused, with a `ProvisioningFailed`
event on the claim. A volume released under `reclaimPolicy: Delete` has its
partition noted on its PersistentVolume, is removed, then the partition is
wiped and dropped, then the PersistentVolume deleted. Under `Retain` it stays.

## Capabilities

edge-update labels its node `capability.platform.meridian/<name>: "true"` for
each capability the host offers, as the platform controller's requirement check
reads them (`meridian_app`'s closed set): `persistent-storage`,
`host-network` and `host-admin` (the edge application administers the unit)
always, `serial-devices` for a USB or ACM serial adapter or a
UART that is there, `gpu` for an NVIDIA, AMD or Intel display controller. The
labels are applied server-side under one field manager, so one the host stops
offering goes.
