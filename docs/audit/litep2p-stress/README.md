# Recorded localhost large-sync resource results

Single release run on Linux; measurements are descriptive, with 200 ms sampling.
See [method and limitations](../../LITEP2P_STRESS.md).

Fixture: 66 mined blocks after genesis, 65 signed deployments; 68,421,370 canonical encoded bytes including genesis.

| Scenario | Sync seconds | Source peak RSS (MiB) | Target peak RSS (MiB) | Source CPU seconds | Target CPU seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 77.71 | 499.96 | 423.16 | 2.01 | 56.37 |
| four-flooders | 87.55 | 502.47 | 428.48 | 18.58 | 57.33 |

Four independent flood identities issued 54,162 requests and received 2,732 replies containing 2,875,793,356 payload bytes. Attempts include failures/rejections, not only admitted work.

Both targets matched the source canonical tip, cumulative work/weight and monetary totals, and both replayed the downloaded chain on a peer-less restart.

The earlier immediate-rejection configuration did not complete the loaded sync during 763.707 seconds of observation. That run was stopped before its 900-second deadline to implement bounded FIFO global-slot waiting. Its CSV is retained as diagnostic evidence; it is not a completed or statistically comparable performance run.

The source serves both scenarios in order and has a warm cache in the loaded case. Sampled RSS includes retained allocator/database/ledger memory and excludes generator processes, kernel socket buffers and external page cache. No fixed RSS cap, multi-hour soak, WAN/NAT result or production-default qualification follows from this run.

Artifacts: [report](report.json), [configuration](configuration.json), [environment](environment.json), [baseline samples](baseline.csv), [loaded samples](four-flooders.csv), [before-queue diagnostic samples](before-slot-queue-four-flooders.csv).
