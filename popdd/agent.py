"""popdd.agent -- the hot-chain manager.

WHY THIS FILE EXISTS. `popdd_agent.py` in the prospector repo re-exports
`from popdd.agent import PopddAgent`, and this package shipped `receipt.py` only, so that import
died with `ModuleNotFoundError: No module named 'popdd.agent'`. The POPDD gate
(`scripts/popdd_verify.py`) reached its signing step and crashed in every checkout on the machine.
Measured 2026-08-18.

The class is lifted verbatim from `/Users/chidionyema/Documents/code/lux/popdd_agent.py`, which
still held the only copy of it. Two renames were needed and nothing else, because the receipt half
of that file had ALREADY been migrated into `popdd/receipt.py`:

    _Receipt      ->  DecisionReceipt
    _hash_receipt ->  hash_receipt

Both are safe. The two dataclasses carry the same nine fields in the same order and both serialise
with `separators=(",", ":")`, and the two hash functions are byte-identical -- same seven keys, same
order, `sort_keys=False`, sha256 over UTF-8. So a chain written by the lux copy verifies against
this one.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from popdd.receipt import GENESIS_HASH, DecisionReceipt, HmacSigner, hash_receipt

__all__ = ["PopddAgent"]


class PopddAgent:
    """Hot-chain POPDD manager for a project.

    Usage:
        agent = PopddAgent.for_project("signalengine")
        agent.sign_verify("formatDate", verdict="PASS", passed=4, total=4)

    The chain auto-saves after every append. On start it loads the most
    recent day's receipt file so receipts accumulate across invocations.
    """

    _CACHE: Dict[str, "PopddAgent"] = {}  # project_name → singleton

    def __init__(
        self,
        project_root: Union[str, Path],
        agent_id: str = "lux-agent",
        key_dir: Union[str, Path] = ".lux/keys",
        receipt_dir: Union[str, Path] = ".lux/receipts",
        auto_save: bool = True,
    ):
        self._root = Path(project_root)
        self._key_path = self._root / key_dir / "agent.pem"
        self._receipt_dir = self._root / receipt_dir
        self._agent_id = agent_id
        self._auto_save = auto_save

        # Ensure directories exist
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._receipt_dir.mkdir(parents=True, exist_ok=True)

        # Load or create signing key
        self._signer = HmacSigner(HmacSigner.load_or_create_key(self._key_path))

        # Load most recent day's receipts to continue the chain
        self._receipts: List[DecisionReceipt] = []
        today_path = self._receipt_dir / f"{date.today()}.jsonl"
        if today_path.exists():
            self._load(today_path)

        # If the most recent file is from a previous day, load it too
        # so we don't break the chain across day boundaries
        all_files = sorted(self._receipt_dir.glob("*.jsonl"))
        if all_files and str(all_files[-1]) != str(today_path):
            self._load(all_files[-1])

    @classmethod
    def for_project(cls, name: str) -> "PopddAgent":
        """Get or create a singleton agent for a known project.

        Known projects:
            signalengine  → ~/Documents/code/signalengine
            lux           → ~/Documents/code/lux
            prospector    → ~/Documents/code/prospector
        """
        if name in cls._CACHE:
            return cls._CACHE[name]

        roots = {
            "signalengine": "~/Documents/code/signalengine",
            "lux": "~/Documents/code/lux",
            "prospector": "~/Documents/code/prospector",
        }
        if name not in roots:
            raise ValueError(f"Unknown project '{name}'. Known: {list(roots)}")

        agent = cls(Path(roots[name]).expanduser())
        cls._CACHE[name] = agent
        return agent

    @classmethod
    def at_path(cls, project_root: Union[str, Path]) -> "PopddAgent":
        """Get or create a singleton agent for an arbitrary path."""
        root = Path(project_root).expanduser().resolve()
        key = str(root)
        if key in cls._CACHE:
            return cls._CACHE[key]
        agent = cls(root)
        cls._CACHE[key] = agent
        return agent

    # ── Signing convenience methods ──────────────────────────────────────

    def sign_verify(self, target: str, **proof_kwargs: Any) -> Dict[str, Any]:
        """Sign a verification result (LUX spec verify, type check, lint pass).

        Example:
            agent.sign_verify("calculateDiscount", verdict="PASS", passed=10000, total=10000)
        """
        return self._append("verify", target, proof_kwargs)

    def sign_edit(self, target: str, **proof_kwargs: Any) -> Dict[str, Any]:
        """Sign a file edit (write, patch, refactor).

        Example:
            agent.sign_edit("src/pricing.py", sha256="abc...", diff_lines=12)
        """
        return self._append("edit", target, proof_kwargs)

    def sign_test_run(self, target: str, **proof_kwargs: Any) -> Dict[str, Any]:
        """Sign a test run.

        Example:
            agent.sign_test_run("critical-tests", passed=69, failed=0, exit_code=0)
        """
        return self._append("test-run", target, proof_kwargs)

    def sign_generic(
        self, action: str, target: str, **proof_kwargs: Any
    ) -> Dict[str, Any]:
        """Sign any action not covered by the three convenience methods.

        Example:
            agent.sign_generic("deploy", "v1.2.3", verdict="PASS")
        """
        return self._append(action, target, proof_kwargs)

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the entire chain. Returns {'valid': bool, 'total': int, ...}."""
        for i, r in enumerate(self._receipts):
            expected_prev = GENESIS_HASH if i == 0 else self._receipts[i - 1].content_hash
            if r.previous_hash != expected_prev:
                return {
                    "valid": False,
                    "total": len(self._receipts),
                    "broken_at": i,
                    "reason": f"previous_hash mismatch at {i}",
                }

            partial = self._partial_from_receipt(r)
            recomputed = hash_receipt(partial)
            if recomputed != r.content_hash:
                return {
                    "valid": False,
                    "total": len(self._receipts),
                    "broken_at": i,
                    "reason": f"content_hash mismatch at {i}",
                }

            import hmac as hmac_mod
            expected_sig = self._signer.sign(r.content_hash)
            if not hmac_mod.compare_digest(r.signature, expected_sig):
                return {
                    "valid": False,
                    "total": len(self._receipts),
                    "broken_at": i,
                    "reason": f"signature invalid at {i}",
                }

        return {"valid": True, "total": len(self._receipts)}

    def receipts(self) -> List[Dict[str, Any]]:
        """Return all receipts as dicts (for display or export)."""
        return [
            {
                "seq": r.sequence,
                "timestamp": r.timestamp,
                "action": r.action,
                "target": r.target,
                "proof": r.proof,
                "content_hash": r.content_hash[:12] + "...",
                "signature": r.signature[:12] + "...",
            }
            for r in self._receipts
        ]

    def summary(self) -> str:
        """Human-readable summary of the chain."""
        if not self._receipts:
            return "  No receipts yet."

        lines = []
        for r in self._receipts:
            lines.append(
                f"  #{r.sequence:>3}  {r.timestamp[:19]}  "
                f"{r.action:>10}  {r.target}  "
                f"hash={r.content_hash[:12]}  sig={r.signature[:12]}"
            )

        result = self.verify_chain()
        status = "✅ VALID" if result["valid"] else f"❌ BROKEN at #{result['broken_at']}"
        lines.append(f"\n  Status: {status}  |  {result['total']} receipts")
        return "\n".join(lines)

    # ── Internal ─────────────────────────────────────────────────────────

    def _append(self, action: str, target: str, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Core append — creates, signs, saves a receipt."""
        previous_hash = (
            GENESIS_HASH
            if not self._receipts
            else self._receipts[-1].content_hash
        )

        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

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

        if self._auto_save:
            self._save()

        return {
            "sequence": receipt.sequence,
            "action": receipt.action,
            "target": receipt.target,
            "content_hash": receipt.content_hash,
            "signature": receipt.signature,
            "total": len(self._receipts),
        }

    def _save(self) -> None:
        """Append-only write to today's JSONL file."""
        # Only rewrite the whole file if we have receipts (first save)
        # After that, we always write all receipts (JSONL is not append-friendly
        # for chain integrity — each line is a complete receipt, so rewriting
        # is fine. The file is per-day and small.)
        path = self._receipt_dir / f"{date.today()}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for r in self._receipts:
                f.write(r.to_json() + "\n")
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except (OSError, NotImplementedError):
            pass

    def _load(self, path: Path) -> None:
        """Load receipts from a JSONL file into the current chain."""
        loaded: List[DecisionReceipt] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                loaded.append(DecisionReceipt(
                    sequence=d["sequence"],
                    timestamp=d["timestamp"],
                    agent_id=d["agent_id"],
                    action=d["action"],
                    target=d["target"],
                    proof=d["proof"],
                    previous_hash=d["previous_hash"],
                    content_hash=d["content_hash"],
                    signature=d["signature"],
                ))
        # Only load if the chain is empty (first load) or if these continue
        # from where we left off (sequence continuity check)
        if not self._receipts:
            self._receipts = loaded
        elif loaded and loaded[0].sequence > 0:
            # Check if the last loaded receipt matches our last one
            if self._receipts[-1].content_hash == loaded[0].previous_hash:
                self._receipts.extend(loaded)
            # else: chain gap — don't load (data integrity first)

    @staticmethod
    def _partial_from_receipt(r: DecisionReceipt) -> Dict[str, Any]:
        return {
            "sequence": r.sequence,
            "timestamp": r.timestamp,
            "agent_id": r.agent_id,
            "action": r.action,
            "target": r.target,
            "proof": r.proof,
            "previous_hash": r.previous_hash,
        }
