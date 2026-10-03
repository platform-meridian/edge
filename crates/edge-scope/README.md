# edge-scope

A flight recorder for a Talos node: what explains a reset or a power cut, kept
in rings on flash. Records are fixed-size, CRC-checked and sequence-numbered,
so a cut tears at most one; a ring that cannot be read is set aside and started
again.

`edge-scope dump` prints every ring, oldest first, one JSON object per line.
The `edge_scope` library reads each format.

## Records

Beside `EDGE_SCOPE_RING` (default `/var/lib/edge-scope/ring.bin`):

| File | Holds | Reader |
|---|---|---|
| `ring.bin` | a sample a second (pressure, memory, load, temperatures, failing checks), and events by `k`: `boot` (how the last boot ended), `time`, `nvme`, `cri`, `stop` | `record::history` |
| `services.bin` | Talos service state changes (`k: "svc"`) | `services::read`, `services::latest` |
| `logs/<source>.bin` | Talos service logs and the kernel log, one ring per source | `logs::read_all` |
| `time.json` | the clock's quality and floor | `clock::Quality` |

## Service states

edge-scope subscribes to machined's events (`EDGE_SCOPE_MACHINED`, as
`os:reader`) and closes its rings when the node starts going down. Each
`machine.ServiceStateEvent` becomes one record:

```json
{"k":"svc","t":1790000000,"boot":"3f2a91bc","id":"d3ab0cl1nd4s73a5b6c0","svc":"etcd","state":"Running","healthy":true,"msg":"Health check successful"}
```

- `t`: when machined announced it, from the event id.
- `boot`: the first eight hex digits of the kernel's boot id.
- `id`: machined's event id; replayed events are recorded once a boot.
- `state`: Talos's name: `Initialized`, `Preparing`, `Waiting`, `Starting`,
  `Running`, `Stopping`, `Finished`, `Failed`, `Skipped`.
- `healthy`: absent while unchecked.
- `msg`: cut to fit the 512-byte record.

A service's last record of a boot is its state. The ring holds 4096 records.
