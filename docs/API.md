# XPARQ Node RPC API

The node exposes an unauthenticated HTTP RPC intended for loopback or a trusted
private network. Run the node and open `/docs` for the interactive API reference,
or fetch `/openapi.json` for tooling and SDK generation.

Amounts are unsigned integer **paqs**. `100,000,000 paqs = 1 XPQ`.

## Transaction submission

`POST /transaction` does not accept JSON. Its body is the canonical Borsh
encoding of `AuthorizedTransaction` with content type
`application/octet-stream`. Generate it with the XPARQ transaction and codec
crates, or use the wallet's `--offline` output.

```bash
curl -X POST \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @transaction.borsh \
  http://127.0.0.1:6666/transaction
```

The response contains the accepted transaction ID:

```json
{"transaction_id":"<64 lowercase hexadecimal characters>"}
```

## Compatibility

Coin IDs returned before height 10,000 use legacy hexadecimal text. Starting at
height 10,000 the account RPC emits `xpq:` plus unpadded base64url. Both formats
remain accepted by the wallet parser. Signature profiles also activate at
height 10,000.

The interactive `/docs` page loads its renderer from a public CDN. The
`/openapi.json` specification itself is embedded in the node binary and remains
available without internet access.
