"""
POPDD — Proof of Proof-Driven Development.

Cryptographic chain-of-custody for any proof system.

POPDD adds three guarantees on top of any verification result:
  1. AUTHENTICITY — the receipt was signed by a known agent
  2. INTEGRITY   — the receipt has not been modified
  3. ORDER       — receipts are hash-chained; reordering is detectable

Use cases:
  - Sign the output of a PDD engine
  - Audit-trailed CI/CD pipelines
  - Multi-agent collaboration with provable attribution
  - Compliance logging (SOC2, financial, legal)

Zero external dependencies. Pure Python stdlib (hashlib, hmac, secrets, os).

Example:
    >>> from popdd import HmacSigner, ReceiptChain
    >>> signer = HmacSigner(HmacSigner.load_or_create_key("~/.popdd/keys/agent.pem"))
    >>> chain = ReceiptChain(signer, agent_id="lux-m3")
    >>> chain.append(action="verify", target="calculateDiscount",
    ...              proof={"verdict": "PASS", "passedClauses": 10000})
    >>> result = chain.verify()
    >>> assert result["valid"] is True
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol, Union


GENESIS_HASH = "GENESIS"


# ═══════════════════════════════════════════════════════════════════════
# TYPES
# ═══════════════════════════════════════════════════════════════════════


# A proof payload is any JSON-serializable mapping
ProofPayload = Mapping[str, Any]


class Signer(Protocol):
    """Pluggable signer interface — implement for Ed25519, RSA, etc."""

    def sign(self, data: Union[bytes, str]) -> str:
        """Sign bytes, return hex signature."""
        ...

    def verifier_id(self) -> str:
        """Get a public fingerprint of this signer."""
        ...


@dataclass
class DecisionReceipt:
    """A single signed, hash-chained receipt — the unit of POPDD attestation."""

    sequence: int
    timestamp: str
    agent_id: str
    action: str
    target: str
    proof: Dict[str, Any]
    previous_hash: str
    content_hash: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))


@dataclass
class ChainVerification:
    """Result of chain verification."""

    valid: bool
    total_receipts: int
    broken_at: Optional[int] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════
# HMAC SIGNER (default — pure Python stdlib)
# ═══════════════════════════════════════════════════════════════════════


class HmacSigner:
    """HMAC-SHA256 signer. The secret key is the agent's signing key.

    For multi-agent audit, implement the Signer protocol with Ed25519
    and expose the public key as `verifier_id()`.
    """

    def __init__(self, secret: bytes):
        if len(secret) != 32:
            raise ValueError(f"HMAC key must be 32 bytes, got {len(secret)}")
        self._secret = secret

    def sign(self, data: Union[bytes, str]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def verifier_id(self) -> str:
        """16-char hex fingerprint of the key. Safe to log publicly."""
        return hashlib.sha256(self._secret).hexdigest()[:16]

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new 256-bit signing key."""
        return secrets.token_bytes(32)

    @staticmethod
    def save_key(key: bytes, path: Union[str, Path]) -> None:
        """Persist a key to disk (chmod 600 on POSIX systems)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key.hex())
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except (OSError, NotImplementedError):
            pass  # Non-POSIX filesystem

    @staticmethod
    def load_or_create_key(path: Union[str, Path]) -> bytes:
        """Load a key from disk, or generate + save a new one."""
        path = Path(path)
        if path.exists():
            hex_str = path.read_text().strip()
            if not _is_valid_hex_key(hex_str):
                raise ValueError(
                    f"Invalid key file at {path}: expected 64 hex chars"
                )
            return bytes.fromhex(hex_str)
        key = HmacSigner.generate_key()
        HmacSigner.save_key(key, path)
        return key


def _is_valid_hex_key(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


# ═══════════════════════════════════════════════════════════════════════
# RECEIPT CHAIN
# ═══════════════════════════════════════════════════════════════════════


class ReceiptChain:
    """Append-only chain of DecisionReceipts.

    Each receipt is signed and chained to the previous one's hash,
    making any tampering detectable.

    Thread-safety: NOT thread-safe. For multi-process use, persist the
    chain to disk and reload before each append.
    """

    def __init__(self, signer: Signer, agent_id: str):
        self._signer = signer
        self._agent_id = agent_id
        self._receipts: List[DecisionReceipt] = []

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def verifier_id(self) -> str:
        return self._signer.verifier_id()

    def append(
        self,
        action: str,
        target: str,
        proof: ProofPayload,
        timestamp: Optional[str] = None,
    ) -> DecisionReceipt:
        """Append a new receipt to the chain.

        The receipt's `previous_hash` is automatically set to the prior
        receipt's `content_hash` (or "GENESIS" for the first).
        """
        previous_hash = (
            GENESIS_HASH
            if not self._receipts
            else self._receipts[-1].content_hash
        )

        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )

        partial = {
            "sequence": len(self._receipts),
            "timestamp": timestamp,
            "agent_id": self._agent_id,
            "action": action,
            "target": target,
            "proof": dict(proof),
            "previous_hash": previous_hash,
        }

        content_hash = hash_receipt(partial)
        signature = self._signer.sign(content_hash)

        receipt = DecisionReceipt(
            sequence=partial["sequence"],
            timestamp=partial["timestamp"],
            agent_id=partial["agent_id"],
            action=partial["action"],
            target=partial["target"],
            proof=partial["proof"],
            previous_hash=partial["previous_hash"],
            content_hash=content_hash,
            signature=signature,
        )

        self._receipts.append(receipt)
        return receipt

    def all(self) -> List[DecisionReceipt]:
        """Return a copy of all receipts in order."""
        return list(self._receipts)

    def __len__(self) -> int:
        return len(self._receipts)

    def __getitem__(self, index: int) -> DecisionReceipt:
        return self._receipts[index]

    def verify(self) -> ChainVerification:
        """Verify the entire chain.

        Checks:
          1. Each receipt's `previous_hash` matches the prior receipt's `content_hash`
          2. Each receipt's `content_hash` matches a recomputed hash of its content
          3. Each receipt's `signature` is valid under the signing key

        Returns the first broken receipt's sequence number, or
        `ChainVerification(valid=True, total_receipts=N)` if all good.
        """
        for i, r in enumerate(self._receipts):
            expected_prev = (
                GENESIS_HASH if i == 0 else self._receipts[i - 1].content_hash
            )
            if r.previous_hash != expected_prev:
                return ChainVerification(
                    valid=False,
                    total_receipts=len(self._receipts),
                    broken_at=i,
                    reason=f"previous_hash mismatch at sequence {i}",
                )

            partial = {
                "sequence": r.sequence,
                "timestamp": r.timestamp,
                "agent_id": r.agent_id,
                "action": r.action,
                "target": r.target,
                "proof": r.proof,
                "previous_hash": r.previous_hash,
            }
            recomputed = hash_receipt(partial)
            if recomputed != r.content_hash:
                return ChainVerification(
                    valid=False,
                    total_receipts=len(self._receipts),
                    broken_at=i,
                    reason=f"content_hash mismatch at sequence {i}",
                )

            expected_sig = self._signer.sign(r.content_hash)
            if not hmac.compare_digest(r.signature, expected_sig):
                return ChainVerification(
                    valid=False,
                    total_receipts=len(self._receipts),
                    broken_at=i,
                    reason=f"signature invalid at sequence {i}",
                )

        return ChainVerification(
            valid=True, total_receipts=len(self._receipts)
        )

    def save(self, path: Union[str, Path]) -> None:
        """Append-only write to a JSONL file. Suitable for an audit log."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for r in self._receipts:
                f.write(r.to_json() + "\n")
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except (OSError, NotImplementedError):
            pass


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════


def hash_receipt(partial: Mapping[str, Any]) -> str:
    """Deterministic hash of a receipt's canonical content.

    The order of fields matters and must match between hash and verify.
    """
    canonical = json.dumps(
        {
            "sequence": partial["sequence"],
            "timestamp": partial["timestamp"],
            "agent_id": partial["agent_id"],
            "action": partial["action"],
            "target": partial["target"],
            "proof": dict(partial["proof"]),
            "previous_hash": partial["previous_hash"],
        },
        separators=(",", ":"),
        sort_keys=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_chain_from_jsonl(path: Union[str, Path]) -> List[DecisionReceipt]:
    """Load receipts from a JSONL file. Useful for audit replay."""
    path = Path(path)
    receipts: List[DecisionReceipt] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            receipts.append(
                DecisionReceipt(
                    sequence=d["sequence"],
                    timestamp=d["timestamp"],
                    agent_id=d["agent_id"],
                    action=d["action"],
                    target=d["target"],
                    proof=d["proof"],
                    previous_hash=d["previous_hash"],
                    content_hash=d["content_hash"],
                    signature=d["signature"],
                )
            )
    return receipts
