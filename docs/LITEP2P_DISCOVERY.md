# Experimental litep2p endpoint discovery

The opt-in `litep2p-devnet` transport supports bootstrap hostnames, bounded peer
exchange and reconnecting through successfully dialed endpoints after restart.
Peer IDs remain mandatory: DNS changes do not replace the pinned transport identity.

```bash
cargo build -p node --locked --no-default-features --features litep2p-devnet
./target/debug/node run --litep2p --data ./data/devnet \
  --p2p 0.0.0.0:27677 --rpc 127.0.0.1:27678 \
  --peer bootstrap.example.com:27677@PEER_ID \
  --public-addr my-node.example.com:27677
```

Replace the example hostnames and peer ID. Install `protoc` before building this
feature. `--public-addr` publishes the stable endpoint with this node's peer ID;
its port must be reachable separately. Binding an unspecified listen address does
not publish that address. A directly bound admissible public IP can be advertised
automatically. This feature does not provision DDNS, port forwarding, or NAT.

## Address policy and DNS

Explicitly configured endpoints may use private IPs or the special hostname
`localhost`. Other DNS names use the existing canonical fully qualified hostname
parser. Configured DNS identities are stored as hostnames, not resolved-IP fallbacks.
On each reconnect attempt, DNS is resolved again with a three-second timeout.
A four-permit semaphore bounds native resolver workers, including workers still
finishing after a caller timeout. At most four supervisor dial attempts are active; at most 32 answers are examined
and four distinct admissible addresses retained per resolution.

Discovered endpoints use the existing public-address policy by default. Every DNS
answer is checked before dial, including IPv4-mapped IPv6, loopback, private,
link-local and reserved-address exclusions. Dial uses a numeric IP multiaddress,
so transport does not independently re-resolve an admitted hostname. If an address
fails, the endpoint backs off and rotates its preferred DNS answer on the next
attempt. Failed dial events release the supervisor attempt only when the event's
address matches that attempt; stale failures cannot clear another address attempt.
A 20-second supervisor timeout provides a fallback for missing dial events.

DNS runs as async tasks alongside network events. The supervisor conservatively
allows new attempts while connected peers plus pending attempts remain below 16;
transport's existing 16 incoming / 16 outgoing connection limits remain in force.

For a local/private devnet, explicitly enable private discovery:

```bash
./target/debug/node run --litep2p --litep2p-private-discovery \
  --data ./data/local-devnet --p2p 127.0.0.1:27679 --rpc 127.0.0.1:27680 \
  --peer localhost:27677@PEER_ID
```

This relaxes the public-address filter for discovered endpoints and DNS answers.
Unspecified, multicast, broadcast and zero-port endpoints remain unusable. Repeat
this flag after restart to reuse private endpoints learned through discovery.
Locally configured private endpoints retain their explicit configuration provenance
when successfully dialed and persisted. That provenance is never accepted from a
network advertisement.

## Bounded exchange and storage

A peer announcement carries up to 16 `HOST:PORT@PEER_ID` endpoints in at most 8 KiB.
Lengths are checked before allocation; decoding does not resolve DNS. Peer exchange
runs when a chain-identity stream opens and every 30 seconds. Announcements use the
existing small unknown-message inbound count/byte bucket, before decode or logging.
The local table holds at most 128 endpoint records. Duplicate advertisements cannot
overwrite a configured record or refresh its lifetime. Self peer IDs are ignored.

Unverified discovered records expire after one hour. Successfully dialed records
have a seven-day cache lifetime. Explicit configuration remains available in the
current process. Candidate selection prefers configured endpoints, then previously
successful endpoints, avoids dialing an already connected peer ID, and retries
failed endpoints with bounded exponential backoff (20 seconds through 1,280 seconds).
Different endpoints for the same identity do not create simultaneous attempts.

Only an outbound endpoint whose authenticated litep2p connection completes a
matching genesis/chain-spec notification handshake is saved. Advertising an endpoint
or accepting an inbound connection does not prove that advertised endpoint reachable.
Saved records use the separate `litep2p-peers-v1` auxiliary key in `xparq.redb`;
they do not change the legacy TCP peer store. Only successful records are persisted,
and stale/future-dated records are excluded on reload. Serialized store size is
bounded to 128 KiB before JSON decode.

After restart, saved endpoints are dialed even without `--peer`. A dead bootstrap
therefore does not prevent contacting a saved reachable peer. Peer exchange relays
this node's advertised endpoint and previously successful endpoints, subject to the
current public/private discovery policy. It never relays raw DNS fallback IPs.

This adds optional announcement type 3 to the existing `/xparq/devnet/announce/2`
protocol. Older builds can continue manual sync but may log an unknown discovery
announcement. Consensus encoding and transport protocol names are unchanged.

## Verification and limits

Unit coverage includes hostile lengths, deduplication, record limits and expiry,
DNS-answer policy changes, private/mapped/reserved addresses, fresh hostname lookup,
configured-address protection, persistence provenance and stale dial failures.
The DNS answer-change test injects different resolver answer sets; it does not
change a live external DNS zone.

The live integration test connects through `localhost`, learns a source through
another node, checks that the original hostname is saved after successful dial,
then stops the bootstrap and restarts the target with no `--peer`. The source adds
a block, and the target reconnects and reaches the same tip through its saved peer.
Local nodes explicitly enable private discovery for this test.

See [verification results](audit/litep2p-discovery-verification.txt). No live public
DDNS update, Internet/NAT campaign, production load test, or Sybil-resistance claim
is included. A fixed endpoint/table/connection budget cannot ensure an honest peer
is available. Transport identity remains Ed25519; account signatures are separate.
