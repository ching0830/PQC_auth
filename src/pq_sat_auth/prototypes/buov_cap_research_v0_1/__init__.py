"""Research-only partial CAP relations; no production issuance backend."""
Backend = None

def verify_issuance(*args, **kwargs):
    raise NotImplementedError("Partial CAP research does not implement pi_iss")
