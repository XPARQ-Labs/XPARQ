# XPARQ local litep2p patches

Upstream: crates.io litep2p 0.15.2, retaining its package metadata, source and
license notices. Registry bookkeeping and the upstream package lockfile are
omitted. XPARQ's workspace lockfile supplies dependency resolution.

Changes:

- `transport/tcp/config.rs` adds `max_pending_connections` (default 32).
- `transport/tcp/mod.rs` drops excess incoming sockets before authentication
  when queued incoming sockets plus pending negotiated connections reach the
  configured threshold. Pending outbound negotiations also occupy this budget.
  Outbound initiation has its own dial limits. Dropping a socket continues polling
  negotiation completions and deadlines, even with a continuously ready listener.
- `notification/config.rs` adds `with_max_handshake_size`; its default preserves
  upstream behavior. The local handshake must fit the requested limit.
- `notification/negotiation.rs` sets the bounded frame codec during handshake and
  restores the notification limit before handing off a negotiated substream.
- `substream/mod.rs` adds an internal codec-limit setter. The existing varint
  decoder checks declared length before allocating its payload buffer.

XPARQ configures eight pending transport negotiations, five-second TCP connection
and substream opening timeouts, and a 64-byte notification handshake. Upstream's
notification handshake exchange deadline remains ten seconds. Automatic inbound
notification acceptance is disabled so both directions validate chain identity.
Protocol names still select the supported protocol version.

Maintain these changes explicitly when upgrading litep2p. Do not edit the Cargo
registry cache to apply patches. See the workspace litep2p hardening documentation
and aggregate/handshake verification records for scope and limitations.

## Request-response lifecycle patch

`request_response/config.rs` adds explicit per-peer inbound concurrency, absolute
inbound frame read timeout, and an independent request size limit. The latter two
limits restore the normal response codec after a valid request is read. Reading
uses the inbound deadline (or the configured outbound timeout when unspecified).

`request_response/mod.rs` holds an owned semaphore permit across reading,
application wait and response writes. It bounds application wait and rejection
close in addition to the existing response-write timeout. A dropped/failed future
releases its original permit; reconnect contexts cannot share that semaphore.
Read/response completions are polled before new transport events to prevent cleanup
starvation. Global concurrency remains bounded, and excess streams are dropped
without awaiting their close. The optional bounded global-slot wait policy below
changes immediate rejection only when explicitly enabled. The upstream request regression's internal tuple is
updated in `request_response/tests.rs` for the carried permit.

The XPARQ node selects two inbound slots per peer, eight globally, a 2,051-byte
request frame cap, five-second frame read / rejection-close deadlines and separate
15-second application wait / response-write deadlines. No response-bandwidth quota
is added by this patch.

## Bounded global-slot waiting patch

`ConfigBuilder::with_max_pending_inbound_requests` optionally admits additional
streams to a FIFO global semaphore wait, bounded by the active limit plus the
pending limit. It defaults to zero (immediate rejection at the active limit).
The per-peer permit is acquired before waiting; no frame is read until the global
permit is acquired. Admission wait expires using the inbound timeout, after which
an admitted request receives a separate frame-read deadline. Both owned permits
are carried into the application/response future. Errors and dropped futures
release their original permits. The internal test tuple carries both permits.

XPARQ selects 8 active requests and 32 additional waiters, with two peer permits
including all phases. No global active-request or response-buffer limit is raised.
The wait postpones frame decoding; existing transport buffering remains separate.
This addresses the measured four-peer contention case without claiming fairness
against arbitrary groups that fill the bounded queue or connection table.
