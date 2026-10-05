# edge-update

Verifies signed update bundles (`edge-bundle`) and applies them to the unit it
runs on, through the node's Talos API and the cluster's Flux. The API is
`proto/edge/update/v1/update.proto`; a console reaches it through whatever
fronts the unit.

## An update, step by step

The status lists the update's steps in order, those still to come included,
each with its state and times. Only the steps the release needs are listed:
a release whose OS the unit already runs has no install, reboot or OS trial.

| Step | What happens |
|---|---|
| upload | chunks arrive, in any order; a dropped connection or a reload resumes |
| verify | the signature, then every file against the signed sums; the unit's checks |
| stage | images imported, the state store copied off, the machine config staged |
| install | the new OS written beside the running one |
| reboot | into the new OS, on trial |
| os trial | until the unit commits the OS |
| stack | the judge updated, then the stack pointed at the new release |
| trial | until the judge commits or rolls the stack back |
| commit | images no kept release names collected |

The bundle's signed head (`SHA256SUMS`, its signature, `MANIFEST` and
`NOTES.md`) is read as soon as the start of the upload has arrived: a bundle
signed by another key, or whose `MANIFEST` this engine cannot take, is refused
before the rest is sent.

One update at a time: `BeginUpload` and `Apply` take a `by`, an opaque name
for other clients. Another's upload of a different bundle is not replaced
until it has been idle for two minutes; the status's `lock` says who holds
the unit.

## Installed sets

A bundle with `components.json` (see `edge-bundle`) is a set of components:
the base or not, and modules. edge-update merges it into the installed set of
the stack the unit runs: a module it brings is installed or updated, one it
does not mention stays as it is, one goes only if the bundle names it in
`remove`, and without a base the unit keeps its own, installer included, so
there is no OS step. It composes the stack for the result, the base's
artifact with `modules/` rewritten (one file of Flux objects per module, and
with `stack.modules` set, a ConfigMap of `MODULES` and each module's MANIFEST
lines), tags it as the bundle's `STACK_TAG` in the repository `stack.url`
names, and keeps the set beside that tag. The release's MANIFEST, refs and
machine config are then the set's, so the judge, rollback and collection
cover the whole set: rolling back returns to the previous one. The release
still says what the bundle itself did: `brings_base`, the `modules` it
brought and those it `removes`, and each of its components names its `owner`
(`base` or a module) and whether the bundle `carried` it. A bundle
without a base on a stack whose set it did not compose is refused, as is one
applied after the stack moved from the one it was verified on.

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
the judge's checks fail on such a trial, an upload and `Verify` are taken
anyway: the trial is ended as failed, with the reason in the history, and
`Apply` moves the stack off it without waiting for a good release. A healthy
trial, or one with a release to roll back to, is never taken over.

## Storage

`GetStorage` says what the image store holds, what only the previous release
holds (kept so a rollback can return to it), and what nothing kept names.
`CollectGarbage` drops the latter, and the previous release's images too if
asked, after which a rollback to it is refused: it has no images to run.
