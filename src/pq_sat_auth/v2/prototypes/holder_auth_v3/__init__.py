"""Experimental holder-signature access profile.

This namespace is deliberately separate from the shared v0.2 protocol parser
and registry.  It is a measurement prototype, not a production access suite.
"""

from .codec import (
    ACCESS_SUITE_ID,
    HOLDER_SUITE_ML_DSA_65,
    CandidateTicketPayloadV3,
    CandidateTicketV3,
    FirstApplicationRecordV3,
    HolderAccessAcceptV3,
    HolderAccessRequestV3,
    SessionActivateV3,
    build_candidate_ticket_fixture,
    decode_access_accept,
    decode_access_request,
    decode_candidate_ticket,
    decode_first_application_record,
    decode_session_activate,
    derive_holder_public_key_binding,
    encode_access_accept,
    encode_access_request,
    encode_candidate_ticket,
    encode_first_application_record,
    encode_session_activate,
)
from .providers import (
    DilithiumPyMLDSA65Provider,
    PQCryptoMLDSA65Provider,
    PQCryptoMLKEM768Provider,
    ProviderUnavailable,
)
from .suite import (
    HandshakeArtifactsV3,
    run_experimental_handshake,
    verify_holder_authenticated_request,
)

EXPERIMENTAL_REFERENCE_ONLY = True
PRODUCTION_READY = False
PROOF_CLOSED = False
PRODUCTION_CLOSED = False

__all__ = [
    "ACCESS_SUITE_ID",
    "HOLDER_SUITE_ML_DSA_65",
    "CandidateTicketPayloadV3",
    "CandidateTicketV3",
    "DilithiumPyMLDSA65Provider",
    "FirstApplicationRecordV3",
    "HandshakeArtifactsV3",
    "HolderAccessAcceptV3",
    "HolderAccessRequestV3",
    "PQCryptoMLDSA65Provider",
    "PQCryptoMLKEM768Provider",
    "ProviderUnavailable",
    "SessionActivateV3",
    "build_candidate_ticket_fixture",
    "decode_access_accept",
    "decode_access_request",
    "decode_candidate_ticket",
    "decode_first_application_record",
    "decode_session_activate",
    "derive_holder_public_key_binding",
    "encode_access_accept",
    "encode_access_request",
    "encode_candidate_ticket",
    "encode_first_application_record",
    "encode_session_activate",
    "run_experimental_handshake",
    "verify_holder_authenticated_request",
]
