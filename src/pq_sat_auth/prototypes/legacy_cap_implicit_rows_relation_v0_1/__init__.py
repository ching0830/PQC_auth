"""LC14 joined local diagnostic. Whole R2 and cryptographic backend stay unresolved."""
Backend=None
full_R2=False
def verify_issuance(*args,**kwargs):
    raise NotImplementedError("No qualified issuance backend")
