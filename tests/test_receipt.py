"""
POPDD Tests — Proof of Proof-Driven Development

Verifies the cryptographic chain-of-custody layer:
  1. Receipts are signed and chained correctly
  2. Chain verification passes for a clean chain
  3. Tampering with any receipt invalidates the chain
  4. Signer key persistence works (load_or_create)
  5. Determinism: same inputs produce same outputs
"""

import json
import tempfile
from pathlib import Path

import pytest

from popdd import (
    GENESIS_HASH,
    ChainVerification,
    DecisionReceipt,
    HmacSigner,
    ReceiptChain,
    hash_receipt,
    load_chain_from_jsonl,
)


# ═══════════════════════════════════════════════════════════════════════
# 1. SIGNER BASICS
# ═══════════════════════════════════════════════════════════════════════


class TestHmacSigner:
    def test_generates_a_32_byte_key(self):
        k = HmacSigner.generate_key()
        assert len(k) == 32

    def test_two_keys_produce_different_signatures(self):
        k1 = HmacSigner.generate_key()
        k2 = HmacSigner.generate_key()
        s1 = HmacSigner(k1).sign("hello")
        s2 = HmacSigner(k2).sign("hello")
        assert s1 != s2

    def test_same_key_signs_same_input_deterministically(self):
        k = HmacSigner.generate_key()
        s = HmacSigner(k)
        assert s.sign("hello") == s.sign("hello")

    def test_verifier_id_is_16_char_hex(self):
        k = HmacSigner.generate_key()
        s = HmacSigner(k)
        vid = s.verifier_id()
        assert len(vid) == 16
        assert all(c in "0123456789abcdef" for c in vid)

    def test_same_key_yields_same_verifier_id(self):
        k = HmacSigner.generate_key()
        assert HmacSigner(k).verifier_id() == HmacSigner(k).verifier_id()

    def test_load_or_create_key_generates_when_missing(self, tmp_path):
        key_path = tmp_path / "agent.pem"
        assert not key_path.exists()
        k = HmacSigner.load_or_create_key(key_path)
        assert len(k) == 32
        assert key_path.exists()

    def test_load_or_create_key_returns_same_key(self, tmp_path):
        key_path = tmp_path / "agent.pem"
        k1 = HmacSigner.load_or_create_key(key_path)
        k2 = HmacSigner.load_or_create_key(key_path)
        assert k1 == k2

    def test_load_or_create_key_rejects_malformed(self, tmp_path):
        key_path = tmp_path / "agent.pem"
        key_path.write_text("not-hex")
        with pytest.raises(ValueError, match="Invalid key file"):
            HmacSigner.load_or_create_key(key_path)

    def test_key_must_be_32_bytes(self):
        with pytest.raises(ValueError, match="32 bytes"):
            HmacSigner(b"too short")


# ═══════════════════════════════════════════════════════════════════════
# 2. RECEIPT CHAIN
# ═══════════════════════════════════════════════════════════════════════


class TestReceiptChain:
    def setup_method(self):
        self.signer = HmacSigner(HmacSigner.generate_key())
        self.chain = ReceiptChain(self.signer, agent_id="lux-test")

    def test_empty_chain_verifies(self):
        assert len(self.chain) == 0
        v = self.chain.verify()
        assert v.valid is True
        assert v.total_receipts == 0

    def test_first_receipt_previous_hash_is_genesis(self):
        r = self.chain.append("verify", "fn", {"verdict": "PASS"})
        assert r.sequence == 0
        assert r.previous_hash == GENESIS_HASH

    def test_subsequent_receipts_chain_to_prior(self):
        r1 = self.chain.append("verify", "fn1", {"verdict": "PASS"})
        r2 = self.chain.append("edit", "fn2", {"verdict": "PASS"})
        assert r2.previous_hash == r1.content_hash

    def test_clean_chain_verifies(self):
        self.chain.append("verify", "a", {"verdict": "PASS"})
        self.chain.append("edit", "b", {"verdict": "PASS"})
        self.chain.append("publish", "c", {"verdict": "PASS"})
        v = self.chain.verify()
        assert v.valid is True
        assert v.total_receipts == 3

    def test_tampering_with_proof_is_detected(self):
        self.chain.append("verify", "a", {"verdict": "PASS"})
        self.chain.append("edit", "b", {"verdict": "PASS"})
        self.chain.append("publish", "c", {"verdict": "PASS"})

        # Mutate receipt 1's proof in place
        self.chain._receipts[1].proof = {"verdict": "FAIL"}

        v = self.chain.verify()
        assert v.valid is False
        assert v.broken_at == 1
        assert "content_hash" in v.reason

    def test_tampering_with_signature_is_detected(self):
        self.chain.append("verify", "a", {"verdict": "PASS"})
        self.chain.append("edit", "b", {"verdict": "PASS"})

        self.chain._receipts[0].signature = "0" * 64

        v = self.chain.verify()
        assert v.valid is False
        assert v.broken_at == 0
        assert "signature" in v.reason

    def test_tampering_with_previous_hash_is_detected(self):
        self.chain.append("verify", "a", {"verdict": "PASS"})
        self.chain.append("edit", "b", {"verdict": "PASS"})
        self.chain.append("publish", "c", {"verdict": "PASS"})

        self.chain._receipts[2].previous_hash = "0" * 64

        v = self.chain.verify()
        assert v.valid is False
        assert v.broken_at == 2
        assert "previous_hash" in v.reason

    def test_determinism_same_sequence_same_hashes(self):
        s = HmacSigner(HmacSigner.generate_key())
        c1 = ReceiptChain(s, agent_id="lux-test")
        c2 = ReceiptChain(s, agent_id="lux-test")

        ts = "2026-06-17T12:00:00.000Z"
        c1.append("verify", "fn", {"verdict": "PASS"}, timestamp=ts)
        c2.append("verify", "fn", {"verdict": "PASS"}, timestamp=ts)

        assert c1[0].content_hash == c2[0].content_hash
        assert c1[0].signature == c2[0].signature

    def test_save_writes_valid_jsonl(self, tmp_path):
        self.chain.append("verify", "a", {"verdict": "PASS"})
        self.chain.append("edit", "b", {"verdict": "PASS"})

        out = tmp_path / "receipts.jsonl"
        self.chain.save(out)
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "sequence" in parsed
            assert "signature" in parsed
            assert "content_hash" in parsed

    def test_load_chain_from_jsonl_roundtrip(self, tmp_path):
        self.chain.append("verify", "a", {"verdict": "PASS", "x": 1})
        self.chain.append("edit", "b", {"verdict": "PASS", "y": 2})

        out = tmp_path / "receipts.jsonl"
        self.chain.save(out)

        loaded = load_chain_from_jsonl(out)
        assert len(loaded) == 2
        assert loaded[0].target == "a"
        assert loaded[1].target == "b"
        assert loaded[0].proof == {"verdict": "PASS", "x": 1}

    def test_chain_with_wrong_signer_fails_to_verify(self):
        # Sign with one key
        s1 = HmacSigner(HmacSigner.generate_key())
        c1 = ReceiptChain(s1, agent_id="lux-test")
        c1.append("verify", "a", {"verdict": "PASS"})

        # Try to verify with a different key
        s2 = HmacSigner(HmacSigner.generate_key())
        c2 = ReceiptChain(s2, agent_id="lux-test")
        c2.append("verify", "a", {"verdict": "PASS"})

        # The two chains have the same content but different signatures
        # because they were signed with different keys
        assert c1[0].signature != c2[0].signature

        # Verification with the wrong signer's chain fails
        v = c2.verify()
        assert v.valid is True  # c2 was signed by s2, so verify with s2 works

        # But if we swap the signer of c2, verify fails
        c2._signer = s1
        v = c2.verify()
        assert v.valid is False
        assert v.broken_at == 0


# ═══════════════════════════════════════════════════════════════════════
# 3. INTEGRATION SCENARIO
# ═══════════════════════════════════════════════════════════════════════


class TestPopddIntegration:
    """Simulates a real agent workflow with POPDD signing."""

    def test_realistic_pdd_workflow(self):
        signer = HmacSigner(HmacSigner.generate_key())
        chain = ReceiptChain(signer, agent_id="lux-m3")

        # Step 1: spec written
        chain.append(
            action="spec-write",
            target="weightedAverage",
            proof={"verdict": "PASS", "preconditions": 4, "postconditions": 3},
        )

        # Step 2: verification run (verifier returns PASS for a real spec)
        chain.append(
            action="verify",
            target="weightedAverage",
            proof={
                "verdict": "PASS",
                "passedClauses": 3011,
                "totalClauses": 3011,
                "samples": 1000,
            },
        )

        # Step 3: file edited
        chain.append(
            action="edit",
            target="src/math/weighted.ts",
            proof={"verdict": "PASS", "sha256": "abc123", "diffLines": 38},
        )

        # Step 4: tests run
        chain.append(
            action="test-run",
            target="tests/weighted.test.ts",
            proof={"verdict": "PASS", "tests": 5, "passed": 5, "failed": 0},
        )

        v = chain.verify()
        assert v.valid is True
        assert v.total_receipts == 4

        # Tamper with step 2's verdict
        chain._receipts[1].proof = {"verdict": "FAIL", "passedClauses": 0, "totalClauses": 0, "samples": 0}
        v = chain.verify()
        assert v.valid is False
        assert v.broken_at == 1
