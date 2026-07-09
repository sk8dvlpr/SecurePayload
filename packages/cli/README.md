# sk8dvlpr/securepayload-cli

Operational CLI for [sk8dvlpr/securepayload](https://github.com/sk8dvlpr/SecurePayload).

## Install

```bash
composer global require sk8dvlpr/securepayload-cli
```

## Commands

```bash
securepayload keys:generate client-a key-v1 --ed25519-server
securepayload keys:rotate client-a key-v1 --grace=86400
securepayload debug:verify -H headers.json -b @body.json --method=POST --path=/v1/pay --protocol-version=3
securepayload test:roundtrip --mode=both --protocol-version=3
```

See [docs/PROTOCOL.md](../../docs/PROTOCOL.md) and [docs/KEY_ROTATION.md](../../docs/KEY_ROTATION.md).
