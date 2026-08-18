"""POPDD — Proof of Proof-Driven Development."""

from popdd.agent import PopddAgent
from popdd.receipt import (
    GENESIS_HASH,
    ChainVerification,
    DecisionReceipt,
    HmacSigner,
    ProofPayload,
    ReceiptChain,
    Signer,
    hash_receipt,
    load_chain_from_jsonl,
)

__version__ = "0.1.0"

__all__ = [
    "GENESIS_HASH",
    "ChainVerification",
    "DecisionReceipt",
    "HmacSigner",
    "PopddAgent",
    "ProofPayload",
    "ReceiptChain",
    "Signer",
    "hash_receipt",
    "load_chain_from_jsonl",
]
