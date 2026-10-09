# Historical body cache resource experiment

The final release run repeats the [shared-payload workload](../ledger-memory/README.md)
on the same machine: 66 mined blocks after genesis, 65 signed 1 MiB program
deployments and 68,421,370 canonical encoded bytes including genesis. Both final
scenario reports have exactly the same tip hash, cumulative work/weight and
monetary totals as the preceding run. Both targets pass peer-less restart/replay.

| Scenario | Source before (MiB) | Source after (MiB) | Target before (MiB) | Target after (MiB) | Sync before (s) | Sync after (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 351.52 | 220.12 | 233.96 | 234.82 | 77.91 | 78.90 |
| four-flooders | 355.30 | 224.21 | 236.40 | 233.50 | 89.83 | 90.15 |

Source sampled peak RSS decreases by approximately 37% in these observations.
Target peaks are approximately unchanged; the fixture has a large active program
registry and private candidate state, which remain in RAM. This result does not
measure a UTXO-heavy workload or demonstrate a bounded process RSS.

## CPU and validation cost

Source CPU seconds: baseline 2.06 -> 3.20, loaded 20.13 -> 48.12. Target CPU
seconds: baseline 55.18 -> 55.43, loaded 59.89 -> 59.14. The loaded final sync
takes 90.15 seconds versus 89.83 previously. Local disk reads and Merkle
commitment verification have a CPU cost; this is not a performance win in every
metric. Byte/request quotas do not impose a global CPU limit.

The preliminary disk-read implementation repeated full VM/operation validation
and used 91.56 source CPU seconds in the loaded scenario. The optimized local
read verifies bounded decoding, pinned height/header and Merkle commitment.
Untrusted admission and replay still perform full validation. Its loaded source
CPU is 48.12 seconds; diagnostic artifacts are retained separately below.

Four flood identities issued 54,674 requests, receiving
2,815 replies with 2,963,161,895 payload bytes.
Attempts include rejected and failed work. The final test passes in 393.78 seconds
including fixture generation, startup and restart checks, which are excluded
from per-scenario resource sampling.

## Scope and artifacts

These are single-run measurements with 200 ms sampling. They are descriptive,
not statistically controlled comparisons or instantaneous maximum guarantees.
The source serves baseline before loaded sync, retaining warm database/allocator
state. No other XPARQ regression suites run during either recorded experiment.
Only source and active target are sampled; generator processes, restart replay,
kernel socket buffers and external filesystem page cache are excluded.

Implementation and remaining stages: [historical body storage](../../HISTORICAL_BODY_CACHE.md).
Commands and correctness evidence: [verification](../disk-body-cache-verification.txt).
Final artifacts: [report](report.json), [configuration](configuration.json),
[environment](environment.json), [baseline samples](baseline.csv),
[loaded samples](four-flooders.csv).

Pre-optimization diagnostic artifacts: [report](before-read-optimization-report.json),
[baseline samples](before-read-optimization-baseline.csv),
[loaded samples](before-read-optimization-four-flooders.csv). These represent a
prior implementation; they are not substituted for final-run results.
