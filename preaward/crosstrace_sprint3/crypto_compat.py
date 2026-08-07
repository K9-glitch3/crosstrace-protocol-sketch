"""Narrow adapter to the frozen P0 authority-status signature domain."""

from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from crosstrace_sketch.protocol import _verify


def verify_authority_status_attestation(
    body: Mapping[str, Any],
    signature: Any,
    public_key: Ed25519PublicKey,
) -> None:
    """Verify exactly the P0 ``AUTHORITY_STATUS_ATTESTATION`` domain."""

    _verify("AUTHORITY_STATUS_ATTESTATION", body, signature, public_key)


__all__ = ["verify_authority_status_attestation"]
