"""Narrow cryptographic adapter to the frozen P0 signing profile.

Only fixed domain labels are exposed.  Keeping the private P0 helpers behind
this module avoids copying their prefix and signature codec into Sprint 2.
"""

from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crosstrace_sketch.protocol import _sign, _verify

_ENDPOINT_DOMAIN = "ENDPOINT_RECORD_ATTESTATION"
_P0_SENDER_DOMAIN = "SENDER_ATTESTATION"
_P0_RECEIVER_DOMAIN = "RECEIVER_ATTESTATION"


def sign_endpoint_attestation(
    body: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> str:
    return _sign(_ENDPOINT_DOMAIN, body, private_key)


def verify_endpoint_attestation(
    body: Mapping[str, Any],
    signature: Any,
    public_key: Ed25519PublicKey,
) -> None:
    _verify(_ENDPOINT_DOMAIN, body, signature, public_key)


def verify_p0_sender_attestation(
    body: Mapping[str, Any],
    signature: Any,
    public_key: Ed25519PublicKey,
) -> None:
    _verify(_P0_SENDER_DOMAIN, body, signature, public_key)


def verify_p0_receiver_attestation(
    body: Mapping[str, Any],
    signature: Any,
    public_key: Ed25519PublicKey,
) -> None:
    _verify(_P0_RECEIVER_DOMAIN, body, signature, public_key)
