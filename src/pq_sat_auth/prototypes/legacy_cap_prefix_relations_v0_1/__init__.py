"""Isolated, fail-closed diagnostic CAP relations; no issuance verifier."""

BACKEND = None
QUALIFIED_2PC = False
GATE = "BLOCKED"


def verify_issuance(*_args, **_kwargs):
    raise NotImplementedError("No full R1/R2 or qualified issuance backend")
