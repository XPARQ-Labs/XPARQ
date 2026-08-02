# Security

## Secret material

Protect:

* wallet JSON files;
* primary and authorization secret keys;
* wallet authorization passwords;
* QCash `.XPQ` bearer files;
* administrative RPC tokens;
* TLS private keys.

Never commit these files, paste them into issue trackers, or expose them in
logs.

## Node exposure

* Expose P2P publicly only when operating a public node.
* Keep RPC on loopback unless remote access is required.
* Use TLS for every non-loopback RPC listener.
* Allow only exact CORS origins.
* Keep administrative RPC separate and protected by a strong token.
* Apply firewall rules and operating-system updates.

## Chain identity

Never reuse databases or wallet files with a different chain identity. Verify
the selected Cargo feature, chain ID, genesis hash, address scheme, and ports
before sending value.

## Verification

Do not trust a peer's claimed height or work. Paqus follows locally validated
cumulative chainwork. Proof consumers should compare tips from independent
peers to reduce eclipse and stale-tip risks.

## QCash

A QCash file is bearer value. Encryption of a transport channel does not
prevent the sender from retaining a copy. Redeem is the strongest settlement
when exclusive control is required.

## Development status

Paqus and experimental SQIsign features require independent cryptographic,
consensus, and implementation review before production-value use. Report
security issues privately to the project maintainers rather than publishing
exploit details first.
