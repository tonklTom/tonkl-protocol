#!/usr/bin/env python3
"""
Tonkl Protocol -- Node-Aware Witness Generator

Queries the running Tonkl node for the current Merkle root and
authentication paths, then assembles Prover.toml witness files for
each of the four circuit types: transfer, merge, split, and mint.

Usage:
    from witness_builder import WitnessBuilder
    from node_client import TonklClient

    client = TonklClient()
    builder = WitnessBuilder(client)

    # Transfer: 2-in / 2-out
    toml = builder.build_transfer(
        inputs=[
            NoteInput(index=0, value=500, owner_sk="0xae0901",
                      owner_pk_x="0x...", owner_pk_y="0x...", rho="7001"),
            NoteInput(index=1, value=500, owner_sk="0xae0901",
                      owner_pk_x="0x...", owner_pk_y="0x...", rho="7002"),
        ],
        outputs=[
            NoteOutput(value=400, owner_pk_x="0x...", owner_pk_y="0x...", rho="8001"),
            NoteOutput(value=590, owner_pk_x="0x...", owner_pk_y="0x...", rho="8002"),
        ],
        fee=10,
        asset_id="1",
    )
    builder.write_toml(toml, "tonkl-transfer/Prover.toml")
"""

import json as _json
import os
import subprocess
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from node_client import TonklClient, MerkleProof

# Tree depth must match the Noir circuits
TREE_DEPTH = 32
ZERO_FIELD = "0x" + "00" * 32


# ─────────────────────────────────────────────────────────────────────
# Crypto Helper (wraps tonkl-prover compute)
# ─────────────────────────────────────────────────────────────────────

class CryptoHelper:
    """
    Computes Poseidon2 hashes, commitments, nullifiers, and key derivation
    by calling the `tonkl-prover compute` subcommand as a subprocess.

    Requires the tonkl-prover binary to be built and accessible.
    """

    def __init__(self, prover_bin: Optional[str] = None):
        if prover_bin is None:
            # Default: look relative to this script's location
            script_dir = Path(__file__).resolve().parent
            candidate = script_dir.parent.parent / "tonkl-prover" / "target" / "release" / "tonkl-prover"
            if candidate.exists():
                self.prover_bin = str(candidate)
            else:
                self.prover_bin = "tonkl-prover"  # Assume on PATH
        else:
            self.prover_bin = prover_bin

    def _compute(self, request: dict) -> dict:
        """Call tonkl-prover compute with a JSON request via stdin."""
        result = subprocess.run(
            [self.prover_bin, "compute"],
            input=_json.dumps(request),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"tonkl-prover compute failed: {result.stderr.strip()}"
            )
        return _json.loads(result.stdout)

    def derive_pk(self, sk: str) -> Tuple[str, str]:
        """Derive public key (pk_x, pk_y) from a secret key."""
        r = self._compute({"op": "derive_pk", "sk": sk})
        return r["pk_x"], r["pk_y"]

    def commitment(
        self, value: str, asset_id: str,
        owner_pk_x: str, owner_pk_y: str, rho: str,
    ) -> str:
        """Compute a note commitment."""
        r = self._compute({
            "op": "commitment",
            "value": value,
            "asset_id": asset_id,
            "owner_pk_x": owner_pk_x,
            "owner_pk_y": owner_pk_y,
            "rho": rho,
        })
        return r["commitment"]

    def nullifier(self, cm: str, owner_sk: str) -> str:
        """Compute a nullifier from a commitment and secret key."""
        r = self._compute({
            "op": "nullifier",
            "cm": cm,
            "owner_sk": owner_sk,
        })
        return r["nullifier"]

    def full_note(
        self, value: str, asset_id: str, sk: str, rho: str,
    ) -> Dict[str, str]:
        """
        Compute everything for a note in one call:
        pk_x, pk_y, commitment, nullifier.
        """
        r = self._compute({
            "op": "full_note",
            "value": value,
            "asset_id": asset_id,
            "sk": sk,
            "rho": rho,
        })
        return r


# ─────────────────────────────────────────────────────────────────────
# Witness data types
# ─────────────────────────────────────────────────────────────────────

@dataclass
class NoteInput:
    """An existing note in the tree that the prover wants to spend."""
    index: int            # Leaf index in the Merkle tree
    value: int            # Note value (plaintext, known to prover)
    owner_sk: str         # Spending secret key (hex)
    owner_pk_x: str       # Owner public key x-coordinate (hex)
    owner_pk_y: str       # Owner public key y-coordinate (hex)
    rho: str              # Randomness / note-age field


@dataclass
class NoteOutput:
    """A new note to create."""
    value: int
    owner_pk_x: str
    owner_pk_y: str
    rho: str


# ─────────────────────────────────────────────────────────────────────
# Serialization helpers (TOML + JSON)
# ─────────────────────────────────────────────────────────────────────

def _quote(v: str) -> str:
    """Wrap a string value in double quotes for TOML."""
    return f'"{v}"'


def _fmt_list(items: list, quote: bool = True) -> str:
    """Format a list as a TOML inline array."""
    if quote:
        return "[" + ", ".join(_quote(str(x)) for x in items) + "]"
    else:
        return "[" + ", ".join(str(x).lower() if isinstance(x, bool) else str(x) for x in items) + "]"


def _toml_lines(kvs: list) -> str:
    """
    Convert a list of (key, value) pairs into TOML text.
    Values are pre-formatted strings.
    """
    lines = []
    for k, v in kvs:
        lines.append(f"{k} = {v}")
    return "\n".join(lines) + "\n"


def _dict_to_toml(data: OrderedDict) -> str:
    """Convert an ordered dict of raw Python values to TOML text."""
    lines = []
    for k, v in data.items():
        if isinstance(v, list):
            if v and isinstance(v[0], bool):
                lines.append(f"{k} = {_fmt_list(v, quote=False)}")
            elif v and isinstance(v[0], list):
                # Nested list (e.g., 2D array for merge merkle paths)
                inner = ", ".join(
                    _fmt_list(sub, quote=not (sub and isinstance(sub[0], bool)))
                    for sub in v
                )
                lines.append(f"{k} = [{inner}]")
            else:
                lines.append(f"{k} = {_fmt_list(v, quote=True)}")
        else:
            lines.append(f'{k} = "{v}"')
    return "\n".join(lines) + "\n"


def _dict_to_json(data: OrderedDict) -> str:
    """Convert an ordered dict of raw Python values to JSON text."""
    return _json.dumps(data)


# ─────────────────────────────────────────────────────────────────────
# Witness Builder
# ─────────────────────────────────────────────────────────────────────

class WitnessBuilder:
    """
    Builds Prover.toml witness files by querying a live Tonkl node
    for Merkle roots and authentication paths.
    """

    def __init__(self, client: TonklClient):
        self.client = client

    def _get_merkle_root(self) -> str:
        """Fetch the current Merkle root from the node."""
        return self.client.get_merkle_root()

    def _get_merkle_proof(self, index: int) -> MerkleProof:
        """Fetch a Merkle authentication path from the node."""
        return self.client.get_merkle_proof(index)

    # ─────────────────────────────────────────────────────────────────
    # Transfer (2-in / 2-out)
    # ─────────────────────────────────────────────────────────────────

    def build_transfer(
        self,
        inputs: List[NoteInput],
        outputs: List[NoteOutput],
        fee: int,
        asset_id: str,
        nf_1: str,
        nf_2: str,
        cm_out_1: str,
        cm_out_2: str,
        merkle_root: Optional[str] = None,
        output_format: str = "toml",
    ) -> str:
        """
        Build a witness for the transfer circuit (2-in / 2-out).

        All public inputs (nf_1, nf_2, cm_out_1, cm_out_2) must be
        pre-computed by the caller using CryptoHelper. The circuit
        constrains these values — incorrect values will cause proving
        to fail.

        If merkle_root is None, fetches the current root from the node.
        Merkle paths are always fetched live from the node.

        output_format: "toml" for Prover.toml (nargo), "json" for
                       tonkl-prover stdin.
        """
        assert len(inputs) == 2, f"Transfer requires exactly 2 inputs, got {len(inputs)}"
        assert len(outputs) == 2, f"Transfer requires exactly 2 outputs, got {len(outputs)}"

        if merkle_root is None:
            merkle_root = self._get_merkle_root()

        # Fetch Merkle proofs for both inputs
        proof1 = self._get_merkle_proof(inputs[0].index)
        proof2 = self._get_merkle_proof(inputs[1].index)

        data = OrderedDict([
            # Public inputs (pre-computed, constrained by circuit)
            ("merkle_root", merkle_root),
            ("nf_1", nf_1),
            ("nf_2", nf_2),
            ("cm_out_1", cm_out_1),
            ("cm_out_2", cm_out_2),
            ("fee", str(fee)),
            ("asset_id", asset_id),
            # Input 1 private witnesses
            ("in1_value", str(inputs[0].value)),
            ("in1_owner_pk_x", inputs[0].owner_pk_x),
            ("in1_owner_pk_y", inputs[0].owner_pk_y),
            ("in1_rho", inputs[0].rho),
            ("in1_owner_sk", inputs[0].owner_sk),
            ("in1_merkle_bits", proof1.index_bits),
            ("in1_merkle_path", proof1.siblings),
            # Input 2 private witnesses
            ("in2_value", str(inputs[1].value)),
            ("in2_owner_pk_x", inputs[1].owner_pk_x),
            ("in2_owner_pk_y", inputs[1].owner_pk_y),
            ("in2_rho", inputs[1].rho),
            ("in2_owner_sk", inputs[1].owner_sk),
            ("in2_merkle_bits", proof2.index_bits),
            ("in2_merkle_path", proof2.siblings),
            # Output 1
            ("out1_value", str(outputs[0].value)),
            ("out1_owner_pk_x", outputs[0].owner_pk_x),
            ("out1_owner_pk_y", outputs[0].owner_pk_y),
            ("out1_rho", outputs[0].rho),
            # Output 2
            ("out2_value", str(outputs[1].value)),
            ("out2_owner_pk_x", outputs[1].owner_pk_x),
            ("out2_owner_pk_y", outputs[1].owner_pk_y),
            ("out2_rho", outputs[1].rho),
        ])

        if output_format == "json":
            return _dict_to_json(data)
        return _dict_to_toml(data)

    # ─────────────────────────────────────────────────────────────────
    # Merge (32-in / 1-out)
    # ─────────────────────────────────────────────────────────────────

    def build_merge(
        self,
        inputs: List[NoteInput],
        out_rho: str,
        fee: int,
        asset_id: str,
        nullifiers: List[str],
        cm_out: str,
        merkle_root: Optional[str] = None,
        pad_pk_x: Optional[str] = None,
        pad_pk_y: Optional[str] = None,
        output_format: str = "toml",
    ) -> str:
        """
        Build a witness for the merge circuit (32-in / 1-out).

        All public inputs (nullifiers[32], cm_out) must be pre-computed
        by the caller using CryptoHelper. Inputs fewer than 32 are
        padded with zero-value dummy notes; caller must include padding
        nullifiers in the nullifiers list.

        All inputs MUST share the same owner_sk.
        """
        assert 1 <= len(inputs) <= 32, f"Merge accepts 1-32 inputs, got {len(inputs)}"

        if merkle_root is None:
            merkle_root = self._get_merkle_root()

        # The merge circuit has a single owner_sk for all inputs
        owner_sk = inputs[0].owner_sk
        if pad_pk_x is None:
            pad_pk_x = inputs[0].owner_pk_x
        if pad_pk_y is None:
            pad_pk_y = inputs[0].owner_pk_y

        # Fetch proofs for real inputs
        proofs = [self._get_merkle_proof(inp.index) for inp in inputs]

        # Pad to 32 inputs with zero-value dummies
        in_values = [str(inp.value) for inp in inputs]
        in_rhos = [inp.rho for inp in inputs]
        merkle_bits_list = [p.index_bits for p in proofs]
        merkle_paths_list = [p.siblings for p in proofs]

        # Pad with zeros
        dummy_bits = [False] * TREE_DEPTH
        dummy_path = [ZERO_FIELD] * TREE_DEPTH
        while len(in_values) < 32:
            in_values.append("0")
            in_rhos.append("0")
            merkle_bits_list.append(dummy_bits)
            merkle_paths_list.append(dummy_path)

        data = OrderedDict([
            ("merkle_root", merkle_root),
            ("nullifiers", nullifiers),
            ("cm_out", cm_out),
            ("fee", str(fee)),
            ("asset_id", asset_id),
            ("owner_sk", owner_sk),
            ("in_values", in_values),
            ("in_rhos", in_rhos),
            ("in_merkle_bits", merkle_bits_list),
            ("in_merkle_paths", merkle_paths_list),
            ("out_rho", out_rho),
        ])

        if output_format == "json":
            return _dict_to_json(data)
        return _dict_to_toml(data)

    # ─────────────────────────────────────────────────────────────────
    # Split (1-in / 32-out)
    # ─────────────────────────────────────────────────────────────────

    def build_split(
        self,
        input_note: NoteInput,
        outputs: List[NoteOutput],
        fee: int,
        asset_id: str,
        nf: str,
        cm_outs: List[str],
        merkle_root: Optional[str] = None,
        output_format: str = "toml",
    ) -> str:
        """
        Build a witness for the split circuit (1-in / 32-out).

        All public inputs (nf, cm_outs) must be pre-computed by the caller
        using CryptoHelper. Outputs fewer than 32 are padded with
        zero-value notes; caller must include padding commitments in cm_outs.
        """
        assert 1 <= len(outputs) <= 32, f"Split accepts 1-32 outputs, got {len(outputs)}"
        assert len(cm_outs) == 32, f"cm_outs must have 32 entries, got {len(cm_outs)}"

        if merkle_root is None:
            merkle_root = self._get_merkle_root()

        proof = self._get_merkle_proof(input_note.index)

        # Pad outputs to 32
        out_values = [str(o.value) for o in outputs]
        out_pk_xs = [o.owner_pk_x for o in outputs]
        out_pk_ys = [o.owner_pk_y for o in outputs]
        out_rhos = [o.rho for o in outputs]

        # Use the input note's public key as the dummy recipient for padding
        pad_pk_x = input_note.owner_pk_x
        pad_pk_y = input_note.owner_pk_y
        while len(out_values) < 32:
            out_values.append("0")
            out_pk_xs.append(pad_pk_x)
            out_pk_ys.append(pad_pk_y)
            out_rhos.append(str(len(out_rhos) + 9000))

        data = OrderedDict([
            ("merkle_root", merkle_root),
            ("nf", nf),
            ("cm_outs", cm_outs),
            ("fee", str(fee)),
            ("asset_id", asset_id),
            ("owner_sk", input_note.owner_sk),
            ("in_value", str(input_note.value)),
            ("in_rho", input_note.rho),
            ("in_merkle_bits", proof.index_bits),
            ("in_merkle_path", proof.siblings),
            ("out_values", out_values),
            ("out_pk_xs", out_pk_xs),
            ("out_pk_ys", out_pk_ys),
            ("out_rhos", out_rhos),
        ])

        if output_format == "json":
            return _dict_to_json(data)
        return _dict_to_toml(data)

    # ─────────────────────────────────────────────────────────────────
    # Mint (0-in / 32-out)
    # ─────────────────────────────────────────────────────────────────

    def build_mint(
        self,
        outputs: List[NoteOutput],
        total_minted: int,
        asset_id: str,
        authority_pk_x: str,
        authority_pk_y: str,
        authority_sk: str,
        cm_outs: List[str],
        output_format: str = "toml",
    ) -> str:
        """
        Build a witness for the mint circuit (0-in / 32-out).

        All public inputs (cm_outs[32]) must be pre-computed by the
        caller using CryptoHelper. Mint does not require a Merkle root
        or proofs — it creates new tokens from nothing, authorized by
        the asset authority key.

        Outputs fewer than 32 are padded with zero-value notes sent
        to the authority public key; caller must include padding
        commitments in cm_outs.
        """
        assert 1 <= len(outputs) <= 32, f"Mint accepts 1-32 outputs, got {len(outputs)}"
        assert len(cm_outs) == 32, f"cm_outs must have 32 entries, got {len(cm_outs)}"

        out_values = [str(o.value) for o in outputs]
        out_pk_xs = [o.owner_pk_x for o in outputs]
        out_pk_ys = [o.owner_pk_y for o in outputs]
        out_rhos = [o.rho for o in outputs]

        # Pad with zero-value notes to the authority key
        while len(out_values) < 32:
            out_values.append("0")
            out_pk_xs.append(authority_pk_x)
            out_pk_ys.append(authority_pk_y)
            out_rhos.append(str(len(out_rhos) + 9000))

        data = OrderedDict([
            ("cm_outs", cm_outs),
            ("total_minted", str(total_minted)),
            ("asset_id", asset_id),
            ("authority_pk_x", authority_pk_x),
            ("authority_pk_y", authority_pk_y),
            ("authority_sk", authority_sk),
            ("out_values", out_values),
            ("out_pk_xs", out_pk_xs),
            ("out_pk_ys", out_pk_ys),
            ("out_rhos", out_rhos),
        ])

        if output_format == "json":
            return _dict_to_json(data)
        return _dict_to_toml(data)

    # ─────────────────────────────────────────────────────────────────
    # File I/O
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def write_toml(content: str, path: str) -> None:
        """Write a Prover.toml string to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    @staticmethod
    def read_commitments_from_public_inputs(
        public_inputs_path: str,
        count: int,
        offset: int = 0,
    ) -> List[str]:
        """
        Read commitment hex values from a bb public_inputs binary file.

        Each field element is 32 bytes big-endian. Returns `count`
        commitments starting at field index `offset`.
        """
        data = Path(public_inputs_path).read_bytes()
        if len(data) % 32 != 0:
            raise ValueError(f"public_inputs size ({len(data)}) not a multiple of 32")

        commitments = []
        start = offset * 32
        for i in range(count):
            chunk = data[start + i * 32 : start + (i + 1) * 32]
            if len(chunk) < 32:
                raise ValueError(f"Not enough data for {count} fields at offset {offset}")
            commitments.append("0x" + chunk.hex())
        return commitments

    @staticmethod
    def read_nullifiers_from_public_inputs(
        public_inputs_path: str,
        count: int,
        offset: int = 0,
    ) -> List[str]:
        """
        Read nullifier hex values from a bb public_inputs binary file.

        Same format as read_commitments_from_public_inputs.
        """
        return WitnessBuilder.read_commitments_from_public_inputs(
            public_inputs_path, count, offset
        )


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def main():
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(
        description="Tonkl Witness Builder -- generate Prover.toml from node state"
    )
    parser.add_argument("--url", default="http://127.0.0.1:9100", help="Node RPC URL")

    sub = parser.add_subparsers(dest="command", required=True)

    # merkle-proof (utility)
    p_mp = sub.add_parser("merkle-proof", help="Fetch and print a Merkle proof")
    p_mp.add_argument("index", type=int, help="Leaf index")

    # mint
    p_mint = sub.add_parser("mint", help="Generate mint witness")
    p_mint.add_argument("--output", "-o", default="Prover.toml", help="Output path")
    p_mint.add_argument("--config", required=True, help="JSON config file for mint params")

    # split
    p_split = sub.add_parser("split", help="Generate split witness")
    p_split.add_argument("--output", "-o", default="Prover.toml", help="Output path")
    p_split.add_argument("--config", required=True, help="JSON config file for split params")

    # transfer
    p_xfer = sub.add_parser("transfer", help="Generate transfer witness")
    p_xfer.add_argument("--output", "-o", default="Prover.toml", help="Output path")
    p_xfer.add_argument("--config", required=True, help="JSON config file for transfer params")

    # merge
    p_merge = sub.add_parser("merge", help="Generate merge witness")
    p_merge.add_argument("--output", "-o", default="Prover.toml", help="Output path")
    p_merge.add_argument("--config", required=True, help="JSON config file for merge params")

    args = parser.parse_args()
    client = TonklClient(args.url)
    builder = WitnessBuilder(client)

    if args.command == "merkle-proof":
        proof = client.get_merkle_proof(args.index)
        root = client.get_merkle_root()
        print(f"Root:  {root}")
        print(f"Index: {proof.index}")
        print(f"Bits:  {proof.index_bits[:8]}...")
        for i, s in enumerate(proof.siblings[:4]):
            print(f"  L{i}: {s}")
        if len(proof.siblings) > 4:
            print(f"  ... ({len(proof.siblings) - 4} more)")

    elif args.command == "mint":
        cfg = _json.loads(Path(args.config).read_text())
        outputs = [
            NoteOutput(
                value=o["value"],
                owner_pk_x=o["owner_pk_x"],
                owner_pk_y=o["owner_pk_y"],
                rho=o["rho"],
            )
            for o in cfg["outputs"]
        ]
        toml = builder.build_mint(
            outputs=outputs,
            total_minted=cfg["total_minted"],
            asset_id=cfg["asset_id"],
            authority_pk_x=cfg["authority_pk_x"],
            authority_pk_y=cfg["authority_pk_y"],
            authority_sk=cfg["authority_sk"],
            cm_outs=cfg["cm_outs"],
        )
        builder.write_toml(toml, args.output)
        print(f"Wrote mint witness to {args.output}")

    elif args.command == "split":
        cfg = _json.loads(Path(args.config).read_text())
        inp = cfg["input"]
        input_note = NoteInput(
            index=inp["index"], value=inp["value"],
            owner_sk=inp["owner_sk"],
            owner_pk_x=inp["owner_pk_x"],
            owner_pk_y=inp["owner_pk_y"],
            rho=inp["rho"],
        )
        outputs = [
            NoteOutput(
                value=o["value"],
                owner_pk_x=o["owner_pk_x"],
                owner_pk_y=o["owner_pk_y"],
                rho=o["rho"],
            )
            for o in cfg["outputs"]
        ]
        toml = builder.build_split(
            input_note=input_note,
            outputs=outputs,
            fee=cfg.get("fee", 0),
            asset_id=cfg["asset_id"],
            nf=cfg["nf"],
            cm_outs=cfg["cm_outs"],
        )
        builder.write_toml(toml, args.output)
        print(f"Wrote split witness to {args.output}")

    elif args.command == "transfer":
        cfg = _json.loads(Path(args.config).read_text())
        inputs = [
            NoteInput(
                index=i["index"], value=i["value"],
                owner_sk=i["owner_sk"],
                owner_pk_x=i["owner_pk_x"],
                owner_pk_y=i["owner_pk_y"],
                rho=i["rho"],
            )
            for i in cfg["inputs"]
        ]
        outputs = [
            NoteOutput(
                value=o["value"],
                owner_pk_x=o["owner_pk_x"],
                owner_pk_y=o["owner_pk_y"],
                rho=o["rho"],
            )
            for o in cfg["outputs"]
        ]
        toml = builder.build_transfer(
            inputs=inputs,
            outputs=outputs,
            fee=cfg.get("fee", 0),
            asset_id=cfg["asset_id"],
            nf_1=cfg["nf_1"],
            nf_2=cfg["nf_2"],
            cm_out_1=cfg["cm_out_1"],
            cm_out_2=cfg["cm_out_2"],
        )
        builder.write_toml(toml, args.output)
        print(f"Wrote transfer witness to {args.output}")

    elif args.command == "merge":
        cfg = _json.loads(Path(args.config).read_text())
        inputs = [
            NoteInput(
                index=i["index"], value=i["value"],
                owner_sk=i["owner_sk"],
                owner_pk_x=i["owner_pk_x"],
                owner_pk_y=i["owner_pk_y"],
                rho=i["rho"],
            )
            for i in cfg["inputs"]
        ]
        toml = builder.build_merge(
            inputs=inputs,
            out_rho=cfg["out_rho"],
            fee=cfg.get("fee", 0),
            asset_id=cfg["asset_id"],
            nullifiers=cfg["nullifiers"],
            cm_out=cfg["cm_out"],
        )
        builder.write_toml(toml, args.output)
        print(f"Wrote merge witness to {args.output}")


if __name__ == "__main__":
    main()
