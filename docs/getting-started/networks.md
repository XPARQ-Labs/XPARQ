# Network identity

This documentation describes the active mainnet core. Infrastructure-specific
variants are intentionally omitted from the operator flow here.

| Network | Chain ID | P2P port | RPC port | Signature mode |
| --- | ---: | ---: | ---: | --- |
| Mainnet | 747 | 5555 | 6666 | ML-DSA-44 |

{% hint style="danger" %}
Never reuse a wallet file or database directory with a different chain
identity. The chain ID, genesis hash, address scheme, consensus feature, and
network magic must match.
{% endhint %}

## Build feature

Mainnet is the default feature:

```bash
--no-default-features --features mainnet
```

Keep paths explicit:

```text
wallets/mainnet.json
data/mainnet/
```

SQIsign remains experimental and is not part of mainnet consensus.
