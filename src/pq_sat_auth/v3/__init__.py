"""Package boundary for the selected PQ-SAT holder-authentication V3 profile.

Only the Category A measurement ABI is frozen.  Ticket, cryptographic,
handshake, and state implementations are intentionally absent until their
separate integration lanes satisfy the preflight contracts.
"""

MEASUREMENT_ABI_VERSION = 1
PROTOCOL_VERSION = 3
PRODUCTION_READY = False

__all__ = [
    "MEASUREMENT_ABI_VERSION",
    "PRODUCTION_READY",
    "PROTOCOL_VERSION",
]
