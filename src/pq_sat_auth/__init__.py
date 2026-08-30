"""Reference system-layer building blocks for PQ satellite authentication.

This package is not a production cryptographic implementation.  The current
modules freeze canonical framing and exercise the one-time ticket state machine
without selecting a PQ AKE, holder authenticator, or durable distributed store.
"""

from .framing import (
    FrameType,
    FrameV1,
    ProtocolEncodingError,
    decode_frame,
    decode_opaque,
    encode_frame,
    encode_opaque,
)
from .identities import TicketUseIdentity, derive_use_key
from .replay import (
    Consumption,
    IdentityConflict,
    InMemoryLinearizableReplayStore,
    InvalidTransition,
    Reservation,
    ReservationNotFound,
    ReserveDisposition,
    ReserveResult,
    TicketUnavailable,
)

__all__ = [
    "Consumption",
    "FrameType",
    "FrameV1",
    "IdentityConflict",
    "InMemoryLinearizableReplayStore",
    "InvalidTransition",
    "ProtocolEncodingError",
    "Reservation",
    "ReservationNotFound",
    "ReserveDisposition",
    "ReserveResult",
    "TicketUnavailable",
    "TicketUseIdentity",
    "decode_frame",
    "decode_opaque",
    "derive_use_key",
    "encode_frame",
    "encode_opaque",
]
