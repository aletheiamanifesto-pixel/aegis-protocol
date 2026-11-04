#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noir_bridge.py - Python bridge for Noir ZK circuits.

Provides compile, prove, verify, and codegen-verifier operations
with automatic fallback to mock proofs in development mode.
"""

import hashlib
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class NoirBridgeError(Exception):
    pass


@dataclass
class ProofResult:
    circuit_name: str
    proof_hex: str
    public_inputs: Dict[str, Any]
    generated_at: int
    is_mock: bool = True
    proof_path: Optional[str] = None


def _is_nargo_available() -> bool:
    """Check if nargo CLI is installed."""
    try:
        result = subprocess.run(
            ["nargo", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_NARGO_AVAILABLE: bool = _is_nargo_available()


def mock_proofs_allowed() -> bool:
    """Mock proofs are accepted ONLY if explicitly enabled (local dev / tests).

    Without AEGIS_ALLOW_MOCK_PROOFS=1 a fake proof is never generated or accepted:
    previously a missing `nargo` was enough to have every proof "valid".
    """
    return os.getenv("AEGIS_ALLOW_MOCK_PROOFS", "").strip().lower() in {"1", "true", "yes"}


def compile_circuit(circuit_path: str) -> bool:
    """
    Compile a Noir circuit using nargo.

    Args:
        circuit_path: Path to the circuit directory (contains Nargo.toml).

    Returns:
        True if compilation succeeded.
    """
    if not _NARGO_AVAILABLE:
        return True  # Mock success in dev mode

    result = subprocess.run(
        ["nargo", "compile"],
        cwd=circuit_path,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise NoirBridgeError(f"Compilation failed: {result.stderr.decode()}")
    return True


def generate_proof(
    circuit_name: str,
    private_inputs: Dict[str, Any],
    public_inputs: Dict[str, Any],
    circuits_dir: str = "./noir_circuits",
) -> ProofResult:
    """
    Generate a ZK proof using a Noir circuit.

    Args:
        circuit_name: Name of the circuit (subdirectory in circuits_dir).
        private_inputs: Private witness inputs.
        public_inputs: Public inputs that go into Prover.toml.
        circuits_dir: Base directory for Noir circuits.

    Returns:
        ProofResult with proof hex and public inputs.
    """
    if not _NARGO_AVAILABLE:
        if not mock_proofs_allowed():
            raise NoirBridgeError("nargo not available and mock proofs disabled (AEGIS_ALLOW_MOCK_PROOFS)")
        return _mock_proof(circuit_name, private_inputs, public_inputs)

    circuit_path = Path(circuits_dir) / circuit_name

    prover_data = {**private_inputs, **public_inputs}
    prover_toml_content = "\n".join(f'{k} = "{v}"' for k, v in prover_data.items())

    prover_toml_path = circuit_path / "Prover.toml"
    prover_toml_path.write_text(prover_toml_content)

    result = subprocess.run(
        ["nargo", "prove"],
        cwd=str(circuit_path),
        capture_output=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise NoirBridgeError(f"Proof generation failed: {result.stderr.decode()}")

    proof_file = circuit_path / "proofs" / f"{circuit_name}.proof"
    if not proof_file.exists():
        raise NoirBridgeError(f"Proof file not found at {proof_file}")

    proof_bytes = proof_file.read_bytes()
    return ProofResult(
        circuit_name=circuit_name,
        proof_hex=proof_bytes.hex(),
        public_inputs=public_inputs,
        generated_at=int(time.time()),
        is_mock=False,
        proof_path=str(proof_file),
    )


def verify_proof(
    circuit_name: str,
    proof: ProofResult,
    circuits_dir: str = "./noir_circuits",
) -> bool:
    """
    Verify a ZK proof using nargo verify.

    Args:
        circuit_name: Name of the circuit.
        proof: ProofResult to verify.
        circuits_dir: Base directory for Noir circuits.

    Returns:
        True if proof is valid.
    """
    if proof.is_mock:
        return _verify_mock(proof)

    if not _NARGO_AVAILABLE:
        raise NoirBridgeError("nargo not available for real proof verification")

    circuit_path = Path(circuits_dir) / circuit_name

    result = subprocess.run(
        ["nargo", "verify"],
        cwd=str(circuit_path),
        capture_output=True,
        timeout=60,
    )
    return result.returncode == 0


def generate_verifier_contract(
    circuit_name: str,
    circuits_dir: str = "./noir_circuits",
    output_dir: str = "./contracts",
) -> str:
    """
    Generate a Solidity verifier contract from a compiled Noir circuit.

    Args:
        circuit_name: Name of the compiled circuit.
        circuits_dir: Base directory for Noir circuits.
        output_dir: Where to write the generated Solidity file.

    Returns:
        Path to generated Solidity file.
    """
    if not _NARGO_AVAILABLE:
        # Return path to stub verifier
        return str(Path(output_dir) / "NoirVerifier.sol")

    circuit_path = Path(circuits_dir) / circuit_name
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["nargo", "codegen-verifier"],
        cwd=str(circuit_path),
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise NoirBridgeError(f"Verifier generation failed: {result.stderr.decode()}")

    generated = circuit_path / "contract" / "plonk_vk.sol"
    target = output_path / f"{circuit_name}_verifier.sol"
    if generated.exists():
        target.write_bytes(generated.read_bytes())
    return str(target)


def _mock_proof(
    circuit_name: str,
    private_inputs: Dict[str, Any],
    public_inputs: Dict[str, Any],
) -> ProofResult:
    """Generate a deterministic mock proof (SHA3-256 based) for dev mode."""
    raw = f"{circuit_name}:{sorted(private_inputs.items())}:{sorted(public_inputs.items())}".encode()
    proof_bytes = hashlib.sha3_256(raw).digest()
    return ProofResult(
        circuit_name=circuit_name,
        proof_hex=proof_bytes.hex(),
        public_inputs=public_inputs,
        generated_at=int(time.time()),
        is_mock=True,
    )


def _verify_mock(proof: ProofResult) -> bool:
    """Mock proofs are valid only in dev mode (AEGIS_ALLOW_MOCK_PROOFS=1)."""
    if not mock_proofs_allowed():
        return False
    return len(proof.proof_hex) == 64  # 32 bytes hex-encoded
