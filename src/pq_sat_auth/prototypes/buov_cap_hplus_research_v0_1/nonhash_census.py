"""H+ private input layout only; no old arithmetic census is reused."""
PUBLIC_BYTES, PRIMARY, PUBLIC_CELLS = 846, 8191, 8192
PRIVATE_BYTES, PRIVATE_BITS = 2030206, 16241648
BEGIN = PUBLIC_CELLS + PRIVATE_BITS
PARTIES, POSITIONS, MU = 2048, 2322, 11
TRACE_ROWS, TRACE_TAIL_COLUMNS, WEIGHT_BITS = 1664, 5024, 6688
FINGERPRINT = bytes.fromhex('8579638797c2fa6f9ef09aef518e81213e566115e042744e5b782d8c49c5f07d')
CR_HEADER = b'PQSCAP01\0\1\0\1\xff\x33' + FINGERPRINT + (5024).to_bytes(4, 'big')
SEMANTIC_LAYOUT = (('CR',5074),('r',72),('h1',48),('A',1966080),('Xi',6976),
                   ('selected_seeds',49152),('SN',16),('pk_H',1952),('e',836))

def xi_layout():
    """Offsets of strict mixed-field packing; there is no per-element padding."""
    cursor, result = 0, []
    for repetition in range(18):
        mu = 12 if repetition < 2 else 11
        result.append(dict(repetition=repetition, mu=mu, constant_offset=cursor,
                           linear_offset=cursor+32, linear_bits=256*mu,
                           encoded_bytes=32+256*mu//8, padding_bits=0))
        cursor += 32+256*mu//8
    if cursor != 6976:
        raise AssertionError('Xi strict layout')
    return tuple(result)
