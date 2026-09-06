"""Signature-gated conditional-opening API for system profile v0.1.

No bare partial-decryption or arbitrary-ciphertext operation is exported.
Cryptographic backends remain explicit abstractions in ``opening.interfaces``.
"""

from .combiner import CombineOutcome, OpeningCombiner
from .gate import OpenShareOutcome, OpenShareService
from .request import OpeningCodecError, OpeningRequest
from .shares import OpenShare

__all__ = [
    "CombineOutcome",
    "OpenShare",
    "OpenShareOutcome",
    "OpenShareService",
    "OpeningCodecError",
    "OpeningCombiner",
    "OpeningRequest",
]
