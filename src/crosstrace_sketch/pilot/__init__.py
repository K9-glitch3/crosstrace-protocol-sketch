"""Credential-free CrossTrace systems-pilot harness.

The pilot uses scripted principals and synthetic actions. It validates the
experimental plumbing and selected local control behaviour; it does not
measure LLM behaviour or establish a comparative safety effect.
"""

from .model import CONDITIONS, PILOT_ID, SCENARIOS

__all__ = ["CONDITIONS", "PILOT_ID", "SCENARIOS"]
