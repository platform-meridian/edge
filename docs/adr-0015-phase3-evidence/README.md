# ADR-0015 phase 3: edge's part, the evidence

Run on 2026-10-27, at edge `5914e05` (talos `543bc1b`, core `9dd8beea`).

The cluster was a stock Talos v1.14.4 VM (`meridian-dev-phase3`, on the
Proxmox host, one control-plane node scheduling workloads, its EPHEMERAL
capped at 12 GiB as the appliance caps it at 30), not a unit built from
Meridian's media: building the media and every edge image was more than the
machine had room for beside the other agents. What runs on a unit and not here
is said under each part.

## Storage: a claim becomes a Talos user volume

edge-update (the commit's debug build) ran on the laptop against the VM: its
Talos API through a loopback forward to the node's apid, with an admin
talosconfig in place of the pod's `os:admin` one, and the VM's kubeconfig.
`edge-local` (Retain, the default) and a second class `edge-local-delete`
(Delete) were applied from `deploy/edge-update.yaml`.

- Two claims (256Mi of `edge-local`, 100M of `edge-local-delete`) and a pod
  mounting both: the engine added `pv-<hex>` UserVolumeConfigs (256 and 96 MiB,
  ext4), Talos made the partitions (`u-pv-…` VolumeStatus, ready), the
  provisioner created `local` PersistentVolumes bound by `claimRef`, and the
  pod ran with both mounted (`df`: `/dev/sda9` 229.9M, `/dev/sda10` 84.5M)
  ([provisioner.log](provisioner.log), [volumes.txt](volumes.txt)).
- On the first try the VM's EPHEMERAL held the whole disk: Talos refused the
  volume ("no disks matched … not enough space"), and the claim stayed Pending
  with a `ProvisioningFailed` event saying so, retried every half-minute.
- Deleting the pod and the Delete-class claim: the PersistentVolume was
  annotated with its partition (`/dev/sda10`), the volume removed from the
  machine config, the partition wiped and dropped (gone from
  `discoveredvolumes`), the PersistentVolume deleted. The Retain-class volume
  stayed.
- The pod wrote `kept` to its Retain volume; after `talosctl reboot` a new pod
  on the same claim read `kept`.
- Volumes the provisioner made before the VM's etcd was wiped (EPHEMERAL reset)
  stayed in the machine config and on the disk (`sda7`, `sda8`): Retain keeps
  data whatever happens to the objects. Nothing collects such an orphan.

Unproven here: an OS update keeping the volumes through the engine's merge
(edge-bundle's `machineconfig` unit tests and edge-update's
`a_provisioned_volume_is_added_while_idle_and_kept_by_every_update` cover it,
against fakes), volume encryption on a unit with TPM-sealed user volumes (unit
tests: a new volume takes the unit's keying), and the pod's own Talos
ServiceAccount.

## Capabilities

The same run labelled the VM's node, server-side applied under
`edge-capabilities`: `persistent-storage`, `host-network`, and `gpu`. The
`gpu` is the laptop's (an Intel display controller in its `/sys`), as
edge-update ran there; on a unit it reads the unit's own sysfs.

## The registry: pushes from core alone

edge-registry (debug build) ran on the laptop with `--push-keys` the VM's
`/system/secrets/kubernetes/kube-apiserver/service-account.pub`, read with
`talosctl read`: one RSA public key, as Talos renders it. Tokens were the VM
apiserver's own, `kubectl create token` for ServiceAccounts made to stand for
core and the controller ([registry-proof.txt](registry-proof.txt)):

| | |
|---|---|
| core, audience `edge-registry`: blobs, then a manifest by tag | 201 |
| the manifest pulled, no token | 200 |
| an app's ServiceAccount; core's token for the apiserver; no token | 401 |
| DELETE as core | 403 |
| DELETE as the controller | 202, then the tag is 404 |

Unproven: the extension service on a unit (its `/system/secrets` mount, and
the restart when the keys appear after it starts), and core's real upload
through `registry_credential = { token_file = … }`, which needs core's
appliance config to have `[apps]` (phase 5).

## Routes: edge-gateway finds them

edge-gateway (debug build) ran in a pod on the VM under its own ServiceAccount
and RBAC from `deploy/edge-gateway.yaml`, with the Gateway API CRDs applied, a
config file holding one static route (`unit.lan`), and a backend on the pod's
loopback ([route-proof.txt](route-proof.txt), [gateway.log](gateway.log)):

| | `martin.unit.lan` |
|---|---|
| no ConfigMap | 404 |
| ConfigMap `map/martin-routes` labelled `edge.meridian/routes`, created | 200, the backend's page |
| label removed | 404 |
| label put back | 200 |
| `routes.yaml` given an `authz_backend` | 404, refused in the log |
| ConfigMap deleted | 404 |

No restart at any step. The k3s dev cluster was not used: edge-gateway does not
run there, it has no Gateway API CRDs, and the other agents' deployments were
on it.

## Tests

- edge: `cargo test --workspace` green but for edge-cni's `install::tests`
  (three; the plugin install into a temp dir) and a flaky edge-state test
  (a different one each run), neither touched; `clippy --workspace -D
  warnings` and `fmt` clean.
- talos: `cli` tests and clippy; `test/verify-portable.sh` (40 checks);
  `test/verify-stack.sh` runs to the end again (141 PASS); its five FAILs are
  app-edge's and core's from earlier phases (app-edge's grant path and env,
  core's Secret rights), not phase 3's.
- core: `meridian_app`, `meridian-app-controller`, `meridian-app`, and
  platform-core's config tests; clippy.
- apps/edge: tests and clippy.
