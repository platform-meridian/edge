# edge-scope

A flight recorder for a Talos node. It keeps what explains a reset or a power
cut in rings on flash that survive both: every record is fixed-size, CRC-checked
and sequence-numbered, so a cut tears at most the record being written, and a
ring that cannot be read is set aside and started again.

`edge-scope dump` prints every ring, oldest first, one JSON object per line.
The `edge_scope` library reads each format for other programs.

## Records

Beside `EDGE_SCOPE_RING` (default `/var/lib/edge-scope/ring.bin`):

| File | Holds | Reader |
|---|---|---|
| `ring.bin` | a sample a second (pressure, memory, load, temperatures, failing checks), and events told apart by `k`: `boot` (how the last boot ended), `time`, `nvme`, `cri`, `stop` | `record::history` |
| `services.bin` | Talos's service state changes (`k: "svc"`) | `services::read`, `services::latest` |
| `logs/<source>.bin` | Talos's service logs and the kernel log, one ring per source | `logs::read_all` |
| `time.json` | the clock's quality and floor | `clock::Quality` |

## Service states

edge-scope subscribes once to machined's event stream (`EDGE_SCOPE_MACHINED`,
as `os:reader`). The same stream tells it when the node starts to go down, and
it closes its rings then. Each `machine.ServiceStateEvent` becomes one record:

```json
{"k":"svc","t":1790000000,"boot":"3f2a91bc","id":"d3ab0cl1nd4s73a5b6c0","svc":"etcd","state":"Running","healthy":true,"msg":"Health check successful"}
```

- `t`: when machined announced it, from the event's id.
- `boot`: the first eight hex digits of the kernel's boot id.
- `id`: machined's event id. On each subscription machined replays the events it
  still holds (its last 1000), and each is recorded once a boot, across restarts.
- `state`: as Talos names it: `Initialized`, `Preparing`, `Waiting`,
  `Starting`, `Running`, `Stopping`, `Finished`, `Failed`, `Skipped`.
- `healthy`: absent while unchecked.
- `msg`: machined's message, cut to fit the 512-byte record.

A service's last record of a boot is its state; the earlier ones are how it got
there. The ring holds 4096 records, several boots' worth.
