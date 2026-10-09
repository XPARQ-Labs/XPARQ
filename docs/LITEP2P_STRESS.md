# Reproducible large-sync resource experiment

This opt-in Linux test mines consensus-valid devnet blocks and syncs their bodies
through the production litep2p node over localhost TCP/Noise/Yamux. It compares an
empty target with no competing peers against another empty target while four
independent transport identities repeatedly request full block bodies. The
experiment measures node RSS and CPU; it does not qualify litep2p as the mainnet
default.

## Run

Install the project's Rust toolchain and `protoc`, then run:

```bash
cargo test --release -p node --locked --no-default-features \
  --features litep2p-devnet --test litep2p_stress \
  large_valid_sync_under_multiple_request_flooders -- --ignored --nocapture
```

The test is ignored in ordinary test runs because it mines a large fixture and
retains databases. It requires Linux `/proc`, `getconf`, and permission to bind
local sockets. Use `--release` for the recorded resource experiment. Debug builds
work but spend substantially more time on fixture creation and validation.

Optional environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `XPARQ_STRESS_DEPLOYMENTS` | `65` | Number of 1 MiB program deployments; supported range 65–256 |
| `XPARQ_STRESS_TIMEOUT_SECONDS` | `900` | Maximum wait for each source startup, target sync or target restart |

The timeout is a wait limit, not a watchdog around fixture mining or the entire
experiment. On failure, the test prints the artifact directory before panicking;
inspect it for progress and node diagnostics. The test terminates its child nodes
and load generators on normal completion and unwinding.

## Workload and correctness

The fixture contains genesis, one funding block, and one signed program deployment
per subsequent block. Each program is exactly 1 MiB of valid XPVM code, with nops
followed by a constant and return. The experiment deploys these programs; it does
not invoke them. Deployment burns are quoted from the actual ledger, the payment
is signed with ML-DSA-44, commitments are computed from the ledger, and every block
is mined and passed through `apply_block` before being persisted with production
storage code. The default fixture exceeds 64 MiB of canonical encoded bodies. The reported
canonical byte total includes genesis, which targets initialize locally; genesis
is not part of the body download.

Both targets start with empty databases. Load generators complete the normal chain
identity handshake, maintain up to eight outstanding requests each, and request
stored, full-size block bodies. The test requires all four identities to issue at
least 64 requests and receive a response, and requires aggregate load responses
above 16 MiB. Attempts include subsequently rejected or failed requests; they are
not counts of admitted storage operations.

Each target must reach the source's exact tip and match cumulative work, weight,
mined amount, burned amount and supply. A subsequent peer-less target restart must
replay those downloaded bodies to the same status. This checks canonical sync and
persistence under the workload; it does not inject malicious block contents or
prove resilience against every cooperating-peer attack.

## Artifacts and measurement

The test prints a unique `/tmp/xparq-litep2p-stress-*` directory and retains:

- `configuration.json`: workload and build configuration.
- `baseline.csv` and `four-flooders.csv`: 200 ms process samples.
- `scenarios.json`: completed scenario results, saved before the next scenario.
- `report.json`: successful experiment summary with canonical status and workload counts.
- Source/target databases and node stdout logs. Target restart replaces its stdout log;
  stderr diagnostics appear in test output.

CSV values are resident bytes from `/proc/PID/status` and user plus system CPU ticks
from `/proc/PID/stat`, converted with `getconf CLK_TCK`. CPU time is relative to the
first sample of each scenario. Average CPU percentage is CPU seconds divided by
sync wall time; 100% represents one fully occupied CPU core. Reported peak RSS is
the maximum observed sample, not a guaranteed instantaneous maximum.

Only the source and active target processes are sampled. Fixture generation, load
generator processes, target restart, kernel socket buffers and filesystem page
cache outside process RSS are excluded. Polling `/status` every 200 ms also consumes
node work. The same source process serves both scenarios, so the second scenario
inherits its warm cache and prior allocator state. Targets are fresh processes.
Results are descriptive measurements, not statistically controlled performance
comparisons or constant-memory guarantees.

Localhost does not model WAN latency, packet loss, NAT or real deployment diversity.
This is a short load experiment, not a multi-hour soak or thousands-of-block test.
For recorded results, see [resource verification](audit/litep2p-stress-verification.txt).

The [shared payload resource report](audit/ledger-memory/README.md) repeats the
same fixture after reducing duplicate historical body/code allocations. The original
measurements above remain historical evidence and are not overwritten.

The [historical body cache report](audit/disk-body-cache/README.md) repeats the
fixture with streaming startup and disk reads for evicted bodies. It records both
RAM reductions and additional CPU cost, including a separate preliminary run.
