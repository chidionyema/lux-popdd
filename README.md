# lux-popdd

**POPDD — Proof of Proof-Driven Development for Python.**

Cryptographic chain-of-custody for any proof system. Zero external dependencies. Pure Python stdlib.

```
┌──────────────────────────────────────────────────────┐
│ ReceiptChain                                          │
│                                                      │
│  Receipt 0 (GENESIS)  →  Receipt 1  →  Receipt 2     │
│  content_hash: a3f2b1  →  hash: 8c4e9d  →  hash: ..  │
│  signature: ed25a1     →  sig: 7fb02c   →  sig: ...   │
│       ↑                  ↑                ↑          │
│   HMAC-SHA256         chained to       chained to    │
│   with agent key      previous         previous      │
└──────────────────────────────────────────────────────┘
```

## Why POPDD

When an AI agent verifies your code, you get a *verdict*. POPDD gives you a *receipt*: a cryptographically signed, hash-chained, tamper-evident record of every action. If anything — including the agent that produced it — modifies the chain after the fact, the chain breaks at exactly that step.

POPDD is the chain-of-custody layer. LUX is the proof engine that uses it. They're independent: POPDD doesn't require LUX, and LUX doesn't require POPDD.

## Install

```bash
pip install lux-popdd
```

For local development:

```bash
pip install -e .
```

## Usage

```python
from popdd import HmacSigner, ReceiptChain

# One-time setup (load or generate signing key)
signer = HmacSigner(HmacSigner.load_or_create_key("./.lux/keys/agent.pem"))

chain = ReceiptChain(signer, agent_id="my-agent")

# Sign any action
chain.append("verify", "calculateDiscount", {"verdict": "PASS", "passedClauses": 10000})
chain.append("edit", "src/pricing.py", {"sha256": "abc123...", "diffLines": 12})
chain.append("publish", "v1.2.3", {"verdict": "PASS"})

# Verify the chain
result = chain.verify()
assert result.valid is True
print(f"Chain valid: {result.valid}, {result.total_receipts} receipts")

# Persist
chain.save("./.lux/receipts/2026-06-17.jsonl")
```

## What POPDD Proves

| Property | How |
|---|---|
| **Authenticity** | Each receipt is signed by the agent's key |
| **Integrity** | Each receipt's content is hashed; signature covers the hash |
| **Order** | Each receipt's `previous_hash` = prior receipt's `content_hash` |
| **Tamper detection** | Any modification breaks the chain at the modified step |
| **Local-only signing** | Keys never leave the host (no remote signing service) |

## What POPDD Does NOT Prove

POPDD is a chain-of-custody layer, not a trust oracle.

- **It does not prove the agent's reasoning was correct** — that's what LUX's L1-L4 proofs are for.
- **It does not prove the agent is honest** — a compromised signing key produces "valid" chains.
- **It does not prove the human wasn't coerced** — out of scope.

For the trust boundary: use hardware-backed keys, human-in-the-loop signing for high-stakes actions, and key rotation policies.

## API

### `HmacSigner`

```python
HmacSigner(key: bytes)
HmacSigner.generate_key() -> bytes
HmacSigner.load_or_create_key(path: str | Path) -> bytes
HmacSigner.save_key(key: bytes, path: str | Path) -> None
signer.sign(data: bytes | str) -> str
signer.verifier_id() -> str  # 16-char hex fingerprint
```

### `ReceiptChain`

```python
ReceiptChain(signer: Signer, agent_id: str)
chain.append(action: str, target: str, proof: dict, timestamp: str | None = None) -> DecisionReceipt
chain.all() -> list[DecisionReceipt]
chain.verify() -> ChainVerification
chain.save(path: str | Path) -> None
chain.verifier_id -> str
```

### `Signer` protocol (for custom algorithms)

```python
class Signer(Protocol):
    def sign(self, data: bytes | str) -> str: ...
    def verifier_id(self) -> str: ...
```

For multi-party audit, implement with Ed25519 using `cryptography` or `pynacl`.

## License

MIT

## Related

- **LUX** — [github.com/chidionyema/lux](https://github.com/chidionyema/lux) — the proof engine that uses POPDD
- **@lux/popdd** — TypeScript implementation of the same API
- **POPDD article** — [the LinkedIn piece on why we built this]
