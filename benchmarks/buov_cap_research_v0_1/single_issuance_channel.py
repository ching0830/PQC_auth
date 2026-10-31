"""Bounded binary pipes for one research issuance, with exact wire accounting.

This codec only frames bytes. The caller authenticates setup, reconstructs the
NCC snapshot and statement, performs actual proof verification, and checks EOF
at its protocol boundary. It does not enable a production issuance interface.

An issued response contains private z. Never log, repr, or hash a response or
complete frame. All public API failures use the same fixed error string and
discard underlying exception messages, including stream exceptions.
"""
from functools import wraps
import json
import struct

MAGIC = b'NIC1\0\1'
SETUP, REQUEST, ISSUED, REJECTED = 1, 2, 3, 4
HEADER = struct.Struct('>6sBI')
U32 = struct.Struct('>I')
HEADER_BYTES = 11
CPK_BYTES = 189232
RECORDS_CAP = 8192
SETUP_IDS_BYTES = 96
STATEMENT_BYTES = 1031
PROOF_CAP = 8 << 20
DIGEST_BYTES = 32
Z_BYTES = 184
MAX_FRAME_BYTES = (8 << 20) + (2 << 10)
ERROR = 'invalid single issuance frame'
_BOUNDS = {
    SETUP: (12 + CPK_BYTES + 2 + SETUP_IDS_BYTES,
            12 + CPK_BYTES + RECORDS_CAP + SETUP_IDS_BYTES),
    REQUEST: (8 + STATEMENT_BYTES + 1, 8 + STATEMENT_BYTES + PROOF_CAP),
    ISSUED: (DIGEST_BYTES + Z_BYTES, DIGEST_BYTES + Z_BYTES),
    REJECTED: (0, 0),
}


class ChannelError(ValueError):
    """Fixed-message codec failure; no frame contents or stream error attached."""


def _public(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            result = function(*args, **kwargs)
        except Exception:
            pass
        else:
            return result
        # Raise outside the handler, so __context__ cannot retain an underlying
        # exception whose message might contain private response bytes.
        raise ChannelError(ERROR)
    return guarded


def _bytes(value, minimum, maximum):
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise ChannelError(ERROR)
    return value


def _exact(reader, count):
    result = bytearray()
    while len(result) < count:
        try:
            part = reader.read(count - len(result))
        except InterruptedError:
            continue
        if type(part) is not bytes or not 0 < len(part) <= count - len(result):
            raise ChannelError(ERROR)
        result.extend(part)
    return bytes(result)


def _write(writer, parts):
    total = 0
    for part in parts:
        view = memoryview(part)
        done = 0
        while done < len(view):
            try:
                count = writer.write(view[done:])
            except InterruptedError:
                continue
            if type(count) is not int or not 0 < count <= len(view) - done:
                raise ChannelError(ERROR)
            done += count
        total += done
    writer.flush()
    return total


def _canonical(records):
    if (type(records) is not dict or len(records) > RECORDS_CAP or
            any(type(k) is not str or type(v) is not str for k, v in records.items())):
        raise ChannelError(ERROR)
    # Bound temporary JSON construction too; escaping can expand this small
    # input, and the exact encoded-byte cap is enforced afterwards.
    if sum(len(k) + len(v) for k, v in records.items()) > RECORDS_CAP:
        raise ChannelError(ERROR)
    raw = json.dumps(records, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    return _bytes(raw, 2, RECORDS_CAP)


def _records(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ChannelError(ERROR)
            result[key] = value
        return result

    def reject_constant(_):
        raise ChannelError(ERROR)

    value = json.loads(raw.decode('ascii'), object_pairs_hook=unique,
                       parse_constant=reject_constant)
    if _canonical(value) != raw:
        raise ChannelError(ERROR)
    # Own record field names, hex widths and snapshot semantics belong to the
    # caller's FullNCCSnapshot.from_records, not this transport codec.
    return value


def _header(kind, size):
    lower, upper = _BOUNDS[kind]
    if not lower <= size <= upper or HEADER_BYTES + size > MAX_FRAME_BYTES:
        raise ChannelError(ERROR)
    return HEADER.pack(MAGIC, kind, size)


class _Payload:
    def __init__(self, reader, size):
        self.reader, self.remaining = reader, size

    def take(self, count):
        if not 0 <= count <= self.remaining:
            raise ChannelError(ERROR)
        self.remaining -= count
        return _exact(self.reader, count)

    def blob(self, minimum, maximum):
        count, = U32.unpack(self.take(U32.size))
        if not minimum <= count <= maximum or count > self.remaining:
            raise ChannelError(ERROR)
        return self.take(count)

    def end(self):
        if self.remaining:
            raise ChannelError(ERROR)


def _frame(reader, kinds):
    magic, kind, size = HEADER.unpack(_exact(reader, HEADER_BYTES))
    if magic != MAGIC or kind not in kinds:
        raise ChannelError(ERROR)
    _header(kind, size)  # Check kind-specific and total caps before payload IO.
    return kind, _Payload(reader, size), HEADER_BYTES + size


@_public
def write_setup(stream, cpk, records, setup_ids):
    """Write CPK, canonical dict[str,str] records, and compiler/setup/trace IDs."""
    _bytes(cpk, CPK_BYTES, CPK_BYTES)
    raw = _canonical(records)
    _bytes(setup_ids, SETUP_IDS_BYTES, SETUP_IDS_BYTES)
    pieces = (U32.pack(len(cpk)), cpk, U32.pack(len(raw)), raw,
              U32.pack(len(setup_ids)), setup_ids)
    header = _header(SETUP, sum(map(len, pieces)))
    return _write(stream, (header, *pieces))


@_public
def read_setup(stream):
    """Read exactly one setup frame, leaving subsequent frames/EOF to caller."""
    _, payload, total = _frame(stream, (SETUP,))
    cpk = payload.blob(CPK_BYTES, CPK_BYTES)
    records = _records(payload.blob(2, RECORDS_CAP))
    setup_ids = payload.blob(SETUP_IDS_BYTES, SETUP_IDS_BYTES)
    payload.end()
    return cpk, records, setup_ids, total


@_public
def write_request(stream, statement, proof):
    """Frame fixed NIFS and bounded proof bytes; this does not verify either."""
    _bytes(statement, STATEMENT_BYTES, STATEMENT_BYTES)
    _bytes(proof, 1, PROOF_CAP)
    header = _header(REQUEST, 8 + len(statement) + len(proof))
    return _write(stream, (header, U32.pack(len(statement)), statement,
                           U32.pack(len(proof)), proof))


@_public
def read_request(stream):
    """Return statement, proof, actual frame bytes, without consuming EOF."""
    _, payload, total = _frame(stream, (REQUEST,))
    statement = payload.blob(STATEMENT_BYTES, STATEMENT_BYTES)
    proof = payload.blob(1, PROOF_CAP)
    payload.end()
    return statement, proof, total


@_public
def write_response(stream, request_digest=None, z=None):
    """Write issued(digest32 || z184), or an empty rejected frame for None/None."""
    if request_digest is None and z is None:
        return _write(stream, (_header(REJECTED, 0),))
    _bytes(request_digest, DIGEST_BYTES, DIGEST_BYTES)
    _bytes(z, Z_BYTES, Z_BYTES)
    return _write(stream, (_header(ISSUED, DIGEST_BYTES + Z_BYTES), request_digest, z))


@_public
def read_response(stream):
    """Return digest, z, frame bytes; rejected is (None, None, 11)."""
    kind, payload, total = _frame(stream, (ISSUED, REJECTED))
    if kind == REJECTED:
        payload.end()
        return None, None, total
    digest, z = payload.take(DIGEST_BYTES), payload.take(Z_BYTES)
    payload.end()
    return digest, z, total
