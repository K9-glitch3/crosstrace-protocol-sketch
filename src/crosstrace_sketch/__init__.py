"""CrossTrace illustrative protocol sketch.

This package is a synthetic feasibility prototype. It is not a production
authorisation system and it contains no CrossTrace experimental results.
"""

from .protocol import (
    ActionGate,
    ConsumeResult,
    GateDecision,
    KeyRegistry,
    PermitStore,
    ProtocolError,
    canonical_json,
    content_id,
    loads_strict,
    make_action,
    make_proposal,
    make_scope,
    receipt_id,
    sign_authority_status,
    sign_receipt,
)

__all__ = [
    "ActionGate",
    "ConsumeResult",
    "GateDecision",
    "KeyRegistry",
    "PermitStore",
    "ProtocolError",
    "canonical_json",
    "content_id",
    "loads_strict",
    "make_action",
    "make_proposal",
    "make_scope",
    "receipt_id",
    "sign_authority_status",
    "sign_receipt",
]

__version__ = "0.1.0"
