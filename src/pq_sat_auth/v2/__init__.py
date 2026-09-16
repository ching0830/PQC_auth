"""Bounded reference implementation of satellite access profile v0.2.

The package intentionally contains no production cryptographic backend.  Its
codecs, relation evaluator, backend contracts, and process-local state model
exist to make the v0.2 protocol specification executable and testable.
"""

PRODUCTION_READY = False
