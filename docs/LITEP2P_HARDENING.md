# Experimental litep2p devnet hardening

The transport remains opt-in through `litep2p-devnet` and `node run --litep2p`.
The default TCP transport, consensus constants, state encoding, and devnet
protocol names are unchanged.

## Local resource limits

| Resource | Limit |
| --- | --- |
| Active header/body sync sessions | 1 |
| Verified headers retained per session | 100,000 |
| Logical block bytes in durable staging | 8 GiB by default; configurable |
| Staging redb cache | 16 MiB |
| Established incoming / outgoing connections | 16 / 16 |
| Accepted peers / tracked outbound requests | 32 / 32 |
| Outbound requests per peer | 1 |
| Active inbound requests in litep2p | 8 active globally; 2 per peer across active/waiting |
| Additional global-slot waiters | 32 / 5-second admission deadline |
| Inbound request frame / read deadline | 2,051 bytes / 5 seconds |
| Application response wait / response write deadline | 15 seconds / 15 seconds |
| Parallel dials | 4 |
| Incoming pending transport admission threshold | 8 |
| TCP connection / substream opening timeout | 5 seconds / 5 seconds |
| Notification handshake frame | 64 bytes |
| Notification handshake exchange timeout | 10 seconds |
| Request timeout | 15 seconds |
| Absolute session lifetime | 24 hours |
| Session without verified progress | 60 seconds |
| Retry cooldown after tracked request or session failure | 30 seconds, doubling to 30 minutes |
| Retained retry histories | 64 peer IDs |

The disk budget is checked before decoding each newly received block. Block order
must match the freshly verified headers and the durable prefix length. Full kernel
execution validates the branch before it becomes canonical.

`node run --litep2p --sync-staging-mib N` configures the logical encoded-body budget
in MiB (2 through 1,048,576). The default is 8,192 MiB. A budget is a local resource
policy, not a consensus limit. redb metadata, copy-on-write overhead and retained
file high-water size require additional disk space; this is not a filesystem quota.

## Durable large-branch sync

Bodies are committed individually to `litep2p-sync.redb` inside the data directory.
On reconnect or restart, the node downloads and verifies headers again, then checks
each cached body against those headers. Only the matching contiguous prefix is
reused; a corrupt, missing or mismatched suffix is discarded. Cache identity binds
the chain specification and common ancestor. A newer advertised tip can reuse a
matching earlier prefix. The cache never supplies authoritative ledger state.

Each session targets the exact tip advertised in its handshake. Headers above that
height are ignored. The verified tip hash, height, cumulative work and cumulative
weight must match the claim. Mining during download therefore does not keep extending
that session's target; subsequent sessions catch up to subsequent tips.

Canonical application reads one cached body at a time into a private ledger.
Invalid blocks or cache read failures leave the canonical ledger and its in-memory cache unchanged.
Canonical storage and explorer indices are replaced in one redb transaction, using
repeatable streaming iteration instead of a second encoded whole-chain vector.
Mempool reconciliation and disconnected-operation recovery retain their existing
semantics. Successful application clears the logical staging rows.

This removes the extra in-memory download body vector and encoded persistence vector.
Headers, active state, ledger snapshots, rollback operations and the private
ledger used for validation still consume memory proportional to history. Canonical
bodies now use a [bounded resident cache and disk reads](HISTORICAL_BODY_CACHE.md). It does
not establish a constant-RSS sync implementation or a total process memory cap. Historical block bodies and deployment/registry code now share immutable allocations across ledger copies; see [shared ledger payloads](LEDGER_MEMORY.md) for compatibility checks and measured results.

## Failure handling

Closing a connection or notification stream clears the peer's pending requests
and in-memory sync session. Committed staging bodies survive this cleanup. Request failures and invalid sync responses release
the session and impose a temporary cooldown. Absolute session expiry is checked
on the periodic three-second tick; successful intermediate responses do not
reset its start time. Expiry may be delayed by synchronous processing in the
network loop. Stale request-failure events cannot remove a newer tracked request.

Retry history survives connection and notification-stream closure. Reopening a
stream does not bypass the sync cooldown: both immediate and periodic tip requests
and configured-peer redials consult it. Repeated tracked failures back off for
30, 60, 120 seconds and so on, capped at 30 minutes. Completing a verified sync
session clears that peer's history; a successful tip response alone does not.
History expires one hour after its latest cooldown ends. At most 64 peer IDs are
retained; inserting another evicts the history with the earliest expiry.

This is a retry policy, not a verdict that the peer is malicious. Network failures,
local resource failures and validation failures all back off. It is process-local,
so restarting this node resets history. Peer-ID churn can evict older histories;
this does not establish Sybil resistance. Validated-chain announcement/transaction
relay and inbound request serving remain separate from outbound sync cooldown;
they use the independent inbound budgets below.

An initial dial failure or failure to queue the first tip request is reported
without terminating the node. Configured peers are retried. Pending requests
are bounded and duplicate tip requests for the same peer are avoided.

Block announcements now detect changes in tip hash, including an equal-height
replacement, rather than requiring a height increase. Persisted Ed25519 transport
identity is reused after restart. This transport identity is separate from the
post-quantum account and consensus signatures.

## Sync peer rotation and failover

Accepted peers enter a bounded FIFO rotation queue. When no sync session, queued
continuation or outbound request is active, one peer receives a tip request on
the three-second tick. That peer moves to the back of the queue. Tip polling is
serial: a fast responder cannot repeatedly win a race against every other peer.
Closed peers are removed; peers in retry cooldown are skipped. Queue size remains
bounded by the 32 accepted-peer cap. With many idle peers, polling one per tick
can delay discovery of a stronger tip by roughly three seconds per eligible peer.

A session expires after 60 seconds without verified header extension, successful
fresh staging-prefix verification or a committed matching body. Invalid responses,
request scheduling and announcements do not extend this progress clock. The
existing 15-second request timeout normally detects a source that stops answering
sooner. Absolute 24-hour expiry still applies even when progress continues.
Timers run on the network loop and do not preempt synchronous validation or IO.

Failure removes the session and outstanding requests, applies retry backoff, and
makes the slot available for the next eligible peer. The replacement downloads
and verifies its headers independently. Matching staged bodies survive the switch;
a different branch discards the mismatching suffix or changes the cache identity.
Canonical application still requires complete kernel validation and atomic storage.
A source that continues supplying valid progress may retain its session until it
finishes or reaches the absolute deadline; this is not session time-slicing.

## Per-peer inbound admission

A count and encoded-byte token bucket runs before announcement decoding, kernel
validation, request storage work and rejection logging. Both budgets must admit a
message; rejection does not debit either. Limits apply to accepted peers and do not
change consensus or the protocol format.

| Traffic | Count burst | Count refill / second | Encoded-byte burst | Byte refill / second |
| --- | --- | --- | --- | --- |
| Requests | 32 | 8 | 64 KiB | 16 KiB |
| Block announcements | 4 | 1 | 16 MiB | 4 MiB |
| Transaction announcements | 256 | 16 | 16 MiB | 1 MiB |
| Unknown / empty announcements | 4 | 1 | 8 MiB | 2 MiB |

Excess requests receive a protocol rejection. Excess announcements are silently
dropped without expensive decoding or per-message logs. Announcement delivery is
best-effort: a transaction dropped under load is not guaranteed to be relayed again.
Block synchronization can retrieve missing canonical blocks independently.

Continuation requests for header/body sync wait at least 125 ms on an asynchronous
25 ms timer, matching the server's eight-per-second request refill. This avoids
routine large downloads consuming the burst and triggering repeated retry backoff.
Only one continuation per active sync peer is queued; disconnect/session cleanup
cancels it, and the timer checks admission/session status before sending.

Peer budgets survive reconnect. Up to 64 entries are retained and expire after
five minutes without inbound activity. A new identity fails closed when the table
is full; it cannot evict another peer's unexpired budget. This can temporarily deny
service to a new healthy identity after identity churn. Restart clears the table.

The application sees messages after litep2p has buffered their bounded wire frame.
These controls therefore limit downstream work, not all transport allocation or
aggregate process CPU. They are combined with the aggregate admission limits below; neither establishes Sybil-resistant peer identity.
Handshake/reconnect setup and outbound sync-response verification are separate paths.

## Transport and notification handshake limits

The workspace pins a local litep2p 0.15.2 source copy under
`depend/network/litep2p`; [patch notes](../depend/network/litep2p/XPARQ_PATCHES.md)
identify the changes. Public upstream configuration only limits established
connections and shares the notification frame limit with the handshake. The local
patch adds admission before transport authentication and an independent handshake
frame limit. Established incoming/outgoing limits remain 16/16.

New incoming sockets are dropped before Noise/Yamux authentication once queued
incoming sockets plus pending negotiated connections reach eight. Already pending
outbound negotiations count toward this admission threshold; outbound initiation
remains separately bounded by four concurrent application dials. This is not an
eight-connection cap on established peers. The rejection path still polls pending
negotiations, preventing listener traffic from starving their deadline processing.

TCP connection negotiation and substream opening each have a five-second timeout.
Notification handshake exchange retains litep2p's ten-second deadline. These are
separate protocol phases, not a single five-second deadline for the whole session.
Timer scheduling and synchronous application work can delay observable cleanup.

Notification handshake frames are limited to 64 bytes, matching the concatenated
32-byte genesis and chain-spec identities. The varint decoder rejects an excessive
declared length before allocating the payload buffer. On successful handshake,
the codec restores the existing notification frame limit so valid blocks still fit.
The receive limit does not remove fixed Noise/Yamux buffering. Wrong chain identity
is rejected before application peer admission; protocol negotiation rejects unknown
protocol names. Automatic inbound notification acceptance is explicitly disabled.

Raw sockets release pending negotiation slots on timeout/error. Notification
negotiation errors retain upstream cleanup; connection and notification close
handlers remove accepted peers, sync rotation entries, continuations and requests.
An established transport connection can outlive a rejected notification stream;
this patch does not claim to force-close those transports or provide per-IP fairness.
Repeated fast handshakes, sustained socket floods, and CPU spent dropping sockets
still require further admission policy. No authenticated peer reputation or Sybil
resistance is introduced.

See [handshake verification](audit/litep2p-handshake-verification.txt).

## Aggregate inbound admission

The existing admission point also applies process-wide count and byte buckets
across all peer IDs. A fresh identity, reconnect, or expiry of per-peer history
cannot reset these shared buckets. Limits are local policy, not consensus rules.

| Traffic | Count burst | Count refill / second | Encoded-byte burst | Byte refill / second |
| --- | --- | --- | --- | --- |
| Requests | 128 | 32 | 256 KiB | 64 KiB |
| Block announcements | 8 | 2 | 32 MiB | 8 MiB |
| Transaction announcements | 512 | 32 | 32 MiB | 2 MiB |
| Unknown / empty announcements | 8 | 2 | 16 MiB | 4 MiB |
| Announcements combined | 1,024 | 64 | 64 MiB | 8 MiB |

Announcement admission requires the per-peer, shared class, and combined
announcement budgets to admit the message. All three are refilled before the
decision; tokens are debited only when all admit it. Requests use their dedicated
service budget and do not consume announcement tokens. Rejection does not consume tokens from any other bucket. A backwards
clock does not refill budgets, and elapsed refill is capped at burst capacity.
Existing rejection and drop behavior is retained. Outbound sync continuation
pacing remains compatible with the request limits.

These limits bound admitted downstream message count and encoded bytes. Request
serving now uses the bounded rotation described below. They do
not cap verification time, total RSS, transport buffering, handshake work, or
outbound sync-response processing. A peer group can consume shared capacity and
temporarily delay healthy announcements; token buckets do not guarantee fair
announcement scheduling.
Restart replenishes process-local budgets. The transport remains opt-in devnet.

See [aggregate admission verification](audit/litep2p-aggregate-verification.txt).

## Fair request serving

Only requests from chain-accepted peers with a supported, structurally valid
request frame enter the service queue. The request size ceiling is 2,051 bytes (opcode, locator framing and 64 hashes);
valid tip, block-hash and bounded header-locator requests fit within this limit.
Malformed and oversized requests are rejected before storage work. The transport
still buffers frames under its existing wire cap before this application check.

Each peer has at most two queued requests, preserving two reserved slots for every
peer among the 32 accepted peers. The queue has a 64-request / 131,264-byte ceiling.
Capacity checks run before per-peer admission tokens are debited. Request count
and byte admission remain 32/8-per-second and 64/16 KiB-per-second per peer.

A separate 31.25 ms asynchronous tick serves one queued request (32 per second).
A served peer moves to the end of the rotation if it has another request. Refilling
its own queue cannot move it ahead of a peer already waiting. The dedicated shared
request count/byte service budget is checked before popping; if exhausted, the
request waits for refill without consuming another per-peer admission token.
Transaction, block, and invalid-announcement traffic cannot consume this budget.
Likewise a request flood cannot consume announcement tokens.

Queued requests expire after two seconds; expiry, connection closure, notification
closure and rejected chain admission release queue bytes and reject pending handles.
Missed service ticks are skipped rather than replayed in a burst. The existing eight
concurrent inbound transport requests remain in place; the application queue limits
are additional ceilings, not an increase in transport frame allocation.

Rotation gives turns to requests that reach and enter the application queue. It does
not reserve raw transport slots or CPU time, guarantee acceptance under a sustained
socket/substream flood, or defeat groups of peer IDs. Transport event scheduling,
synchronous storage work and response writes can delay service and expiry. Serving
is limited by message count and incoming request bytes. Encoded responses also
pass the independent outgoing byte admission below. Announcement validation still
runs directly under its own budgets, so sustained expensive validation can delay the
service timer. No global process CPU quota or hard response-time bound is claimed.

See [fair request verification](audit/litep2p-fairness-verification.txt).

## Inbound substream lifecycle

The local request-response patch counts a peer's inbound slot across frame reading,
global-slot waiting, application response wait and response writing. Each peer has two semaphore permits;
the existing global eight-request cap remains. A permit moves with its request and
is released by RAII on rejection, read error, timeout, completion or protocol teardown.
Excess substreams are dropped before their request payload is read or allocated.
An old connection owns a separate semaphore generation, so an old completion cannot
release permits from a reconnected peer's new context.

Request frames have an independent 2,051-byte codec limit before payload allocation,
while the response codec restores the existing block-sized limit. The five-second
read deadline covers the entire frame, including varint prefix and partial payload;
receiving intermediate bytes does not reset it. The request-response configuration
uses a separate 15-second application-wait deadline and retains the existing
15-second response-write deadline. Rejection closes are bounded by five seconds.
These are per-phase deadlines, not a single five-second request lifetime.

Completed IO and timer futures are processed before new transport input in the
request-response actor; transport events still precede application commands.
This avoids a continuously ready substream-event source starving bounded cleanup.
Stale completions still check peer/request membership, and their owned permits
remain attached to their original semaphore. The application service queue retains
its independent two-second expiry and disconnect cleanup.

The limits prevent one peer from retaining all eight global inbound request slots.
They do not reserve capacity against four or more cooperating peer IDs or guarantee
wall-clock cleanup if the runtime or application is blocked. Outgoing response byte
admission is described below. Upstream fixed transport buffering and canonical
history memory remain separate.

See [substream verification](audit/litep2p-substream-verification.txt).

## Bounded waiting for global request slots

Immediate global-slot rejection allowed four peers, each retaining two slots, to
repeatedly deny another connected peer admission before its request reached the
application's fair service queue. The large-body resource experiment exposed this
transport-level contention independently of application request and byte quotas.

XPARQ now permits up to 32 additional inbound streams to wait for one of the eight
global slots. Owned global semaphore permits remain attached through frame reading,
application response wait, response writes and cleanup. Semaphore waiting is FIFO;
new arrivals cannot reclaim a released slot ahead of an already registered waiter.
Completed IO/admission futures are polled before new transport events.

The combined waiting/active stream count is capped at 40. The two per-peer permits
also include waiting, so a single identity cannot fill the waiting queue. Overflow
is dropped before reading the frame. Each wait expires after five seconds;
admission then starts a separate five-second complete-frame read deadline. Queue
waiting does not decode or allocate a request payload. Transport/socket buffering
remains separate and is not eliminated by postponing frame decoding.

Disconnect/error/timeout completion drops the original owned permits. Global
permits belong to the protocol instance; peer permits belong to the connection's
original context, so stale completion cannot release a reconnected peer's permits.
The optional vendored builder defaults to zero additional waiters, preserving
immediate rejection for callers that do not select this policy.

This fixes the tested four-identity request workload, not arbitrary cooperating-peer
admission. A larger group can still fill the bounded waiting queue, exhaust aggregate
service/byte quotas, occupy connections or delay work until phase deadlines. It does
not establish Sybil resistance or a hard healthy-peer response-time guarantee.

Real TCP/Noise/Yamux regressions verify FIFO admission behind occupied slots, queue
and peer overflow, waiting expiry, retained global ownership after another waiter's
timeout, and subsequent successful service. See the [resource experiment](LITEP2P_STRESS.md)
and [verification record](audit/litep2p-stress-verification.txt).

## Outgoing response byte admission

Every served request-response payload must pass both a per-peer and a process-wide
byte bucket after encoding and before it is handed to the transport. Block replies
and tip/header replies use independent buckets, so block downloads cannot consume
the capacity reserved for tip/header replies.

| Response class | Per-peer burst / refill | Global burst / refill |
| --- | --- | --- |
| Block | 16 MiB / 8 MiB per second | 64 MiB / 32 MiB per second |
| Tip and headers | 8 MiB / 4 MiB per second | 16 MiB / 8 MiB per second |

Charging includes the encoded payload and its unsigned-varint length prefix,
including error payloads. It excludes Noise, Yamux and TCP overhead. Both buckets
must admit the entire frame before either is debited. Exhaustion rejects the
request without retaining the response for a later retry. Failed writes do not
refund admission; repeated disconnects cannot reclaim charged bytes.

Peer history survives reconnect for five minutes of inactivity. The table retains
at most 64 peer IDs and fails closed for new identities while full; unexpired
entries cannot be evicted to obtain fresh capacity. New identities still share the
global buckets. Restart replenishes these process-local limits.

These are local serving policies and do not change block validity. A legitimate
busy downloader can receive a rejected request and use existing retry/backoff and
staging-prefix recovery. Admission occurs after storage access and serialization;
it does not bound their CPU or temporary allocation cost. Announcement relay is
outside these response buckets. The limits do not establish a whole-process memory,
CPU, wire-bandwidth or Sybil-resistance guarantee.

The transport fixture sends synthetic block-sized payloads over real TCP/Noise/Yamux
using the production admission implementation and a fixed budget clock: 16 MiB of
charged traffic exhausts one peer, its next request is rejected, and another peer
still receives a response. Unit checks cover shared exhaustion, atomic debit,
refill, independent control capacity, reconnect retention and oversized responses.
See [egress verification](audit/litep2p-egress-verification.txt).

## Current limitations

A branch exceeding 100,000 headers, the configured logical disk budget or the
24-hour session lifetime is rejected locally without partial canonical application.
These bodies are not declared consensus-invalid. Session failures preserve durable
bodies for a later attempt, subject to fresh verification. Headers are not resumed.
The transport remains opt-in devnet; this change does not qualify it as the mainnet
default. Legacy TCP peers cannot speak this wire protocol.

NAT parity, CPU-aware admission, fairness across cooperating identities and
default-transport migration need further evaluation. Bounded endpoint discovery and DNS
reconnect support are described in [litep2p discovery](LITEP2P_DISCOVERY.md).
The original audit's legacy TCP download memory finding remains separate: that
transport still collects downloaded bodies in memory.

## Verification

Install `protobuf-compiler` (`protoc`) before building this optional dependency.
Run the bounded-session regression tests and transport lifecycle tests:

```bash
cargo test -p node --locked --no-default-features --features litep2p-devnet --bin node litep2p_devnet::tests
cargo test -p node --locked --no-default-features --features litep2p-devnet --test litep2p_e2e -- --test-threads=1
```

The staging tests cover quota boundaries, corrupt-suffix repair, branch identity,
5,000 stored entries and a resumed cache exceeding 64 MiB. These two stress fixtures
exercise storage and codec bounds; they are not 5,000 mined consensus blocks or a
64 MiB live network benchmark. Node regression tests also inject a mid-branch read
failure and reject an invalid second block without changing canonical state.

Integration tests cover three-node signed transaction relay, confirmation,
reconnection, stable transport identity, restart persistence and stronger-fork
reorganization. A durable-prefix test seeds two real mined cached bodies to simulate
an interrupted download, then verifies reuse against a newer three-block tip and
canonical persistence after restart.

See [large-sync verification results](audit/litep2p-large-sync-verification.txt).
The separate [resource experiment](LITEP2P_STRESS.md) transfers more than 64 MiB
of mined consensus-valid bodies over localhost, compares an empty target with and
without four request-flooding identities, and samples node RSS and CPU. It does not
replace a multi-hour soak, thousands-of-block experiment, fuzzing campaign or
real-world NAT test.

Retry-policy regression results: [backoff verification](audit/litep2p-backoff-verification.txt).

Inbound admission results: [inbound verification](audit/litep2p-inbound-verification.txt).

Peer rotation/failover results: [failover verification](audit/litep2p-failover-verification.txt).

Hostname bootstrap, bounded endpoint exchange and reconnect persistence: [discovery](LITEP2P_DISCOVERY.md).
