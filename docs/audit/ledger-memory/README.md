# Shared ledger payload resource results

The release experiment repeats the [original workload](../litep2p-stress/README.md)
after sharing block bodies and program code across ledger copies. The fixture is
identical: 66 mined blocks after genesis, 65 signed 1 MiB deployments and
68,421,370 canonical encoded bytes including genesis. Both new scenarios have
exactly the same canonical tip, cumulative work/weight and monetary totals as the
original report. Both complete a peer-less restart/replay successfully.

## Sampled peak resident memory

| Scenario | Process | Before (MiB) | After (MiB) | Reduction |
| --- | --- | ---: | ---: | ---: |
| baseline | source | 499.96 | 351.52 | 29.7% |
| baseline | target | 423.16 | 233.96 | 44.7% |
| four-flooders | source | 502.47 | 355.30 | 29.3% |
| four-flooders | target | 428.48 | 236.40 | 44.8% |

## New run timing

| Scenario | Sync seconds | Source CPU seconds | Target CPU seconds |
| --- | ---: | ---: | ---: |
| baseline | 77.91 | 2.06 | 55.18 |
| four-flooders | 89.83 | 20.13 | 59.89 |

The four independent flood identities issued 56,487 requests and received
2,806 replies with 2,953,688,198 payload bytes. Attempts include rejections
and failures, not only admitted work. All four identities participated.

The test passed in 380.73 seconds including fixture creation, startup and restart
checks; those phases are excluded from per-scenario resource sampling.

## Interpretation and evidence

These are two single-run observations on the same machine, not a statistically
controlled comparison or a guaranteed percentage reduction for every workload.
Sampling is every 200 ms; peaks are observed samples, not instantaneous maxima.
The source serves baseline before the loaded scenario and retains warmed caches.
No other XPARQ regression suites ran during the recorded experiment. Source/target
RSS includes allocator and database allocations but excludes generator processes,
restart replay, kernel socket buffers and external filesystem page cache.
CPU/time differences do not establish a performance improvement.

Sharing reduces duplicate payload allocations. Historical blocks, metadata and
journals still scale with history, and independently decoded data can have separate
allocations. This result does not establish a fixed RAM cap or production readiness.

See [implementation and limits](../../LEDGER_MEMORY.md),
[measurement method](../../LITEP2P_STRESS.md),
[verification commands](../ledger-memory-verification.txt),
[report](report.json), [configuration](configuration.json),
[environment](environment.json), [baseline samples](baseline.csv), and
[loaded samples](four-flooders.csv). Original results remain unchanged.
