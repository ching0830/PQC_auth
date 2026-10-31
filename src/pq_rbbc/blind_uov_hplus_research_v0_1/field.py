"""H+(p)_i = chi_i * f_p(chi_i), BEFORE adding the unscaled Mhat.

Field arithmetic and strict input checks reuse the unchanged polynomial basis.
The party-field lift is the F2-linear map applied to each coefficient bitplane;
GF64 elements are never interpreted as GF11/GF12 elements.
"""
from pq_rbbc.blind_uov_pqsat_v0_1.field import (
    consistency_hash as _legacy_hash, decode_element, encode_element, gf_inv, gf_mul,
)
from .parameters import FieldId


def consistency_hash(vector_2048: bytes, points: tuple[int, int, int, int]) -> bytes:
    evaluated = _legacy_hash(vector_2048, points)  # Canonical strict ABI checks.
    return b''.join(encode_element(FieldId.GF_2_64, gf_mul(
        FieldId.GF_2_64, decode_element(FieldId.GF_2_64, evaluated[8*i:8*i+8]), point
    )) for i, point in enumerate(points))


__all__ = ('consistency_hash', 'decode_element', 'encode_element', 'gf_inv', 'gf_mul')
