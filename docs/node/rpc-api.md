# RPC API

The default mainnet public RPC base URL is:

```text
http://127.0.0.1:6666
```

## Public endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Health check |
| GET | `/status` | Node and synchronization status |
| GET | `/metrics` | Prometheus-style metrics |
| GET | `/chain` | Chain identity and parameters |
| GET | `/stats` | Chain statistics |
| GET | `/peers` | Connected peers |
| GET | `/balance/{address}` | Account balance |
| GET | `/accounts` | Explorer account view |
| GET | `/mempool` | Pending transactions |
| GET | `/qcash/mempool` | Pending QCash transactions |
| GET | `/blocks/latest` | Latest canonical block |
| GET | `/blocks/{height}` | Block by height |
| GET | `/blocks/hash/{hash}` | Block by hash |
| GET | `/tx/{hash}` | Transaction lookup |
| GET | `/address/{address}` | Address activity |
| POST | `/tx` | Submit a signed Transfer transaction |
| POST | `/qcash/tx` | Submit a signed QCash transaction |

Examples:

```bash
curl http://127.0.0.1:6666/status
curl http://127.0.0.1:6666/blocks/latest
curl http://127.0.0.1:6666/balance/P1...
```

Submit canonical signed transaction bytes as hexadecimal:

```bash
curl -X POST http://127.0.0.1:6666/tx \
  -H 'Content-Type: application/json' \
  -d '{"tx":"SIGNED_TRANSACTION_HEX"}'
```

## Authenticated proofs

```text
GET /proof/account/{address}
GET /proof/qcash/{coin_id}
```

Proof bundles contain canonical Borsh encoded as hexadecimal. They bind state
to a verified header chain and proof-of-work tip. Clients should still compare
tips from independent peers to reduce stale-tip and eclipse risk.

An optional validated checkpoint can reduce the returned header path:

```text
/proof/account/{address}?checkpoint_height=100&checkpoint_hash={hash}
```

## Administrative endpoints

These routes are available only on the separately configured admin listener:

```text
POST /peers/add
GET  /mining/template
POST /mining/submit
POST /rollback-issues/{issue_id}/retry
```

Authenticate with:

```bash
curl -H "Authorization: Bearer $PAQUS_RPC_ADMIN_TOKEN" \
  http://127.0.0.1:6667/mining/template?miner=P1...
```

Never expose the admin listener without TLS, network controls, and a strong
token.
