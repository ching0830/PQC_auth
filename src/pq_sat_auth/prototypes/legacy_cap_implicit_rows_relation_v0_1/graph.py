"""LC14 same-witness full291B compiler/evaluator with shared theta D, test-only.

ALLOC y=A*B+C stores three prior-variable LCs; R1CS C includes implicit(y,1).
ASSERT A*B=C has no output. Terms are sorted/index-unique/nonzero GF64.
No retained decoded graph AST, no old Arena or old guard modifications.
"""
from array import array
import hashlib
import io
import struct

from .contract import FINGERPRINT, PRIVATE_BYTES, bridge_offsets, bridge_target, tape_port, MPLAIN_START
from . import reference as lc2
from . import reference as lc3
from .reference import RC, RHO

HEADER = struct.Struct(">4sHH8I")
ARITY = struct.Struct(">H")
TERM = struct.Struct(">IQ")
PUBLIC_BITS, PRIMARY, PRIVATE_BITS = 256, 1023, PRIVATE_BYTES * 8
CR_START, P_START, MHAT_START, H1_START, R_START = 1024, 41616, 43664, 43920, 44304
PARTY_START, SLOPE_START, SEED_START, PREFIX_START = 44880, 46928, 46944, 47136
PREFIX_EXTRA_START = CR_START + 7571 * 8
PREFIX_THIRD_START = CR_START + 9636 * 8
SALT_START, BEGIN = CR_START + 50 * 8, 1 + PRIMARY + PRIVATE_BITS
PADDED_VARIABLES, PADDED_ROWS = 407552, 413696
MAX_VARIABLES, MAX_ROWS, MAX_NNZ = 407336, 411697, 3163552
MAX_ARITY, MAX_GRAPH_BYTES = 2050, 37615391
MODULUS = 0x1000000000000001b
ZERO, ONE = (), ((0, 1),)


def bits(raw):
    if type(raw) is not bytes:
        raise ValueError("exact bytes")
    return tuple((byte >> j) & 1 for byte in raw for j in range(8))


def const_bits(raw):
    return [((), bit) for bit in bits(raw)]


def span(start, count):
    return [((index,), 0) for index in range(start, start + count)]


def bit_sum(expressions):
    active, constant = set(), 0
    for indices, value in expressions:
        constant ^= value
        for index in indices:
            if index in active:
                active.remove(index)
            else:
                active.add(index)
    return tuple(sorted(active)), constant


def bit_lc(bit):
    indices, constant = bit
    return (((0, constant),) if constant else ()) + tuple((index, 1) for index in indices)


def canon(terms):
    result = {}
    for index, coefficient in terms:
        if type(index) is not int or index < 0 or type(coefficient) is not int or not 0 <= coefficient < (1 << 64):
            raise ValueError("GF64 term")
        value = result.get(index, 0) ^ coefficient
        if value:
            result[index] = value
        else:
            result.pop(index, None)
    if len(result) > MAX_ARITY:
        raise ValueError("LC arity")
    return tuple(sorted(result.items()))


def gf_mul(a, b):
    if a < 2:
        return b if a else 0
    if b < 2:
        return a if b else 0
    result = 0
    for _ in range(64):
        if b & 1:
            result ^= a
        b >>= 1
        carry = a >> 63
        a = (a << 1) & ((1 << 64) - 1)
        if carry:
            a ^= 0x1b
    return result


class Writer:
    def __init__(self, stream):
        self.stream, self.next, self.rows, self.nnz, self.allocs = stream, BEGIN, 0, 0, 0
        self.stages, self.chi_round_nnz = {}, []
        self.rounds, self.permutations = 0, 0
        self.inline_theta_by_round = [0] * 120
        self.shared_D_outputs = 0
        self.inline_support_counts = [0] * 4
        self.first_multi_chi = None

    def snapshot(self):
        return self.rows, self.next, self.nnz, self.stream.tell()

    def stage(self, name, start):
        end = self.snapshot()
        self.stages[name] = dict(rows=end[0] - start[0], variables=end[1] - start[1],
                                nnz=end[2] - start[2], encoded_bytes=end[3] - start[3],
                                first_row=start[0], first_byte=start[3])

    def emit(self, allocate, a, b, c):
        if type(allocate) is not int or allocate not in (0, 1):
            raise ValueError("row flag")
        lcs = tuple(canon(lc) for lc in (a, b, c))
        if any(index >= self.next for lc in lcs for index, _ in lc):
            raise ValueError("prior-variable rule")
        added = sum(map(len, lcs)) + allocate
        if self.rows >= MAX_ROWS or self.nnz + added > MAX_NNZ:
            raise ValueError("row/nnz guard")
        if allocate and self.next >= MAX_VARIABLES:
            raise ValueError("projection variable cutoff")
        if self.stream.tell() + 7 + 12 * sum(map(len, lcs)) > MAX_GRAPH_BYTES:
            raise ValueError("raw graph byte cap before write")
        self.stream.write(bytes([allocate]))
        for lc in lcs:
            self.stream.write(ARITY.pack(len(lc)))
            for term in lc:
                self.stream.write(TERM.pack(*term))
        self.rows += 1
        self.nnz += added
        if allocate:
            result = self.next
            self.next += 1
            self.allocs += 1
            return result

    def linear_bit(self, expressions, *, inline=False):
        indices, constant = bit_sum(expressions)
        if inline:
            if len(indices) > 3 or not 0 <= self.rounds < 120:
                raise ValueError("selected theta support/round")
            self.inline_theta_by_round[self.rounds] += 1
            self.inline_support_counts[len(indices)] += 1
            return indices, constant
        output = self.emit(1, tuple((index, 1) for index in indices), ONE, ZERO)
        return (output,), constant

    def chi(self, a, b, c):
        # Each expression is a parity of previously proven Boolean wires.
        # Extract a's constant into the returned affine handle, not a free hint.
        for indices, constant in (a, b, c):
            if (len(indices) > 3 or constant not in (0, 1) or
                    indices != tuple(sorted(set(indices))) or
                    any(type(index) is not int or not 0 < index < self.next for index in indices)):
                raise ValueError("Boolean multi-affine chi induction")
        if self.first_multi_chi is None and max(len(bit[0]) for bit in (a, b, c)) > 1:
            self.first_multi_chi = dict(row=self.rows, byte=self.stream.tell(), next=self.next)
        av, ac = a
        output = self.emit(1, bit_lc((b[0], b[1] ^ 1)), bit_lc(c),
                           tuple((index, 1) for index in av))
        return (output,), ac

    def equal_bits(self, a, b):
        self.emit(0, bit_lc(bit_sum((a, b))), ONE, ZERO)

    def equal_fields(self, a, b):
        self.emit(0, ((a, 1), (b, 1)), ONE, ZERO)

    def pack64(self, value):
        if len(value) != 64:
            raise ValueError("PACK64 width")
        terms = []
        for j, bit in enumerate(value):
            terms.extend((index, coefficient << j) for index, coefficient in bit_lc(bit))
        return self.emit(1, terms, ONE, ZERO)

    def field_add(self, a, b):
        return self.emit(1, ((a, 1), (b, 1)), ONE, ZERO)

    def field_mul(self, a, b):
        return self.emit(1, ((a, 1),), ((b, 1),), ZERO)


def select_inline_theta(global_round, flat_index):
    if type(global_round) is not int or type(flat_index) is not int:
        raise ValueError("integer selector")
    return 0 <= global_round < 120 and 0 <= flat_index < 1600


def coordinate_offsets(coordinate):
    from .contract import coordinate_offsets as offsets
    return offsets(coordinate)


def coordinate_starts(coordinate):
    party, slope = coordinate_offsets(coordinate)
    return CR_START + 8 * party, CR_START + 8 * slope


def prefix_start(coordinate):
    from .contract import prefix_port
    return prefix_port(coordinate)[2]


def prefix_bits():
    return span(PREFIX_START, 8) + span(PREFIX_EXTRA_START, 8) + span(PREFIX_THIRD_START, 8)

def full_tape_private_bits():
    return prefix_bits() + span(94632, 2304)


def permutation(writer, state):
    if len(state) != 1600:
        raise ValueError("Keccak state")
    for constant in RC:
        c = [writer.linear_bit([state[(x + 5 * y) * 64 + z] for y in range(5)])
             for x in range(5) for z in range(64)]
        # This 320-bit D is shared by all five y lanes: actual common-subexpression reuse.
        d = [writer.linear_bit((c[((x + 4) % 5) * 64 + z],
                                c[((x + 1) % 5) * 64 + (z + 63) % 64]))
             for x in range(5) for z in range(64)]
        writer.shared_D_outputs += len(d)
        theta = [writer.linear_bit((state[(x + 5 * y) * 64 + z], d[x * 64 + z]),
                                   inline=select_inline_theta(writer.rounds, (x + 5 * y) * 64 + z))
                 for y in range(5) for x in range(5) for z in range(64)]
        rotated = [None] * 1600
        for x in range(5):
            for y in range(5):
                for z in range(64):
                    rotated[(y + 5 * ((2 * x + 3 * y) % 5)) * 64 +
                            (z + RHO[x + 5 * y]) % 64] = theta[(x + 5 * y) * 64 + z]
        before = writer.nnz
        state = [writer.chi(rotated[(x + 5 * y) * 64 + z],
                            rotated[((x + 1) % 5 + 5 * y) * 64 + z],
                            rotated[((x + 2) % 5 + 5 * y) * 64 + z])
                 for y in range(5) for x in range(5) for z in range(64)]
        writer.chi_round_nnz.append(writer.nnz - before)
        for z in range(64):
            state[z] = state[z][0], state[z][1] ^ ((constant >> z) & 1)
        writer.rounds += 1
    writer.permutations += 1
    return state


def shake_prefix(writer, data):
    if not 0 < len(data) < 2176 or len(data) % 8:
        raise ValueError("one-or-two-block fixed SHAKE caller")
    if len(data) < 1088:
        state = list(data) + const_bits(b"\x1f")
        state += [((), 0)] * (1600 - len(state))
    else:
        state = permutation(writer, list(data[:1088]) + [((), 0)] * 512)
        remainder = data[1088:]
        for i, bit in enumerate(remainder):
            state[i] = bit_sum((state[i], bit))
        for j, bit in enumerate(bits(b"\x1f")):
            index = len(remainder) + j
            state[index] = state[index][0], state[index][1] ^ bit
    state[1087] = state[1087][0], state[1087][1] ^ 1
    return permutation(writer, state)


def consistency_frame():
    domain = lc2.DOMAIN
    return (const_bits(struct.pack(">H", len(domain)) + domain + struct.pack(">HI", 2, 32)) +
            span(1, 256) + const_bits(struct.pack(">I", 48)) + span(H1_START, 384))


def tape_frame():
    domain = lc3.TAPE_DOMAIN
    return (const_bits(struct.pack(">H", len(domain)) + domain + struct.pack(">HI", 5, 32)) +
            span(1, 256) + const_bits(struct.pack(">I", 48)) + span(SALT_START, 384) +
            const_bits(struct.pack(">IH", 2, 2)) + const_bits(struct.pack(">IH", 2, 0)) +
            const_bits(struct.pack(">I", 24)) + span(SEED_START, 192))


def encode(stream):
    if type(stream) is not io.BytesIO or stream.tell() != 0 or stream.seek(0, 2) != 0:
        raise ValueError("empty in-memory BytesIO only; raw graph never written to disk")
    stream.write(bytes(HEADER.size))
    writer = Writer(stream)
    start = writer.snapshot()
    for index in list(range(1, 257)) + list(range(1024, BEGIN)):
        writer.emit(0, ((index, 1),), ((0, 1), (index, 1)), ZERO)
    for index in range(257, 1024):
        writer.emit(0, ((index, 1),), ONE, ZERO)
    writer.stage("inputs", start)

    start = writer.snapshot()
    points_bits = shake_prefix(writer, consistency_frame())[:256]
    writer.stage("consistency_keccak", start)
    start = writer.snapshot()
    coeff = [writer.pack64(span(P_START + 64 * j, 64)) for j in range(32)]
    points = [writer.pack64(points_bits[64 * j:64 * (j + 1)]) for j in range(4)]
    mhat = [writer.pack64(span(MHAT_START + 64 * j, 64)) for j in range(4)]
    alpha = [writer.pack64(span(CR_START + 146 * 8 + 64 * j, 64)) for j in range(4)]
    alpha_checks = []
    for point, mh, al in zip(points, mhat, alpha):
        acc = coeff[-1]
        for item in reversed(coeff[:-1]):
            acc = writer.field_add(writer.field_mul(acc, point), item)
        alpha_checks.append((writer.field_add(acc, mh), al))
    writer.stage("gf64_horner", start)

    start = writer.snapshot()
    for left, right in alpha_checks:
        writer.equal_fields(left, right)
    for left, right in zip(span(P_START, 576), span(R_START, 576)):
        writer.equal_bits(left, right)
    for actual, expected in zip(span(CR_START, 400), const_bits(lc2.CR_HEADER)):
        writer.equal_bits(actual, expected)
    for actual, expected in zip(span(1, 256), const_bits(FINGERPRINT)):
        writer.equal_bits(actual, expected)
    writer.stage("lc1_equalities", start)

    start = writer.snapshot()
    reciprocals = lc2.reciprocal_table()
    coordinate_ports = []
    for coordinate in range(24):
        party_start, slope_start = coordinate_starts(coordinate)
        coordinate_ports.append(dict(coordinate=coordinate, party_start=party_start,
                                     slope_start=slope_start, first_row=writer.rows,
                                     first_byte=stream.tell()))
        parties = span(party_start, 2048)
        for bit in range(11):
            selected = [party for party, reciprocal in zip(parties, reciprocals) if (reciprocal >> bit) & 1]
            if len(selected) != 1024 or parties[-1] in selected:
                raise ValueError("GF11 finite reciprocal plane")
            writer.emit(0, bit_lc(bit_sum(selected + span(slope_start + bit, 1))), ONE, ZERO)
        writer.emit(0, bit_lc(bit_sum(parties + span(CR_START + 8 * 466 + coordinate, 1) +
                                    span(P_START + coordinate, 1))), ONE, ZERO)
        for bit in span(slope_start + 11, 5):
            writer.equal_bits(bit, ((), 0))
    writer.stage("gf11_dense", start)

    start = writer.snapshot()
    frame = tape_frame()
    if len(frame) != 162 * 8:
        raise ValueError("actual canonical tape frame")
    state = shake_prefix(writer, frame)
    tape_bits = list(state[:1088])
    for count in (1088,146):
        state = permutation(writer,state)
        tape_bits.extend(state[:count])
    writer.stage("tape_keccak", start)
    start = writer.snapshot()
    private_bits = full_tape_private_bits()
    for actual, expected in zip(tape_bits,private_bits[:2322]):
        writer.equal_bits(actual,expected)
    writer.stage("full_tape_equalities",start)
    start = writer.snapshot()
    for bit in private_bits[2322:]:
        writer.equal_bits(bit,((),0))
    writer.stage("full_tape_padding",start)
    start = writer.snapshot()
    join_byte_offsets, join_row_indices = [], []
    for coordinate in range(24):
        join_byte_offsets.append(stream.tell())
        join_row_indices.append(writer.rows)
        writer.equal_bits(span(prefix_start(coordinate), 1)[0],
                          span(coordinate_starts(coordinate)[0], 1)[0])
    writer.stage("prefix_join", start)

    start=writer.snapshot()
    bridge_ports=[]
    for b in range(20):
        p,sl=bridge_offsets(b)
        party_start,slope_start=1024+8*p,1024+8*sl
        target,delta=bridge_target(b)
        bridge_ports.append(dict(column=b,tape_coordinate=2047+b,party_start=party_start,
            slope_start=slope_start,plain_target=target,delta_port=delta,
            first_row=writer.rows,first_byte=stream.tell()))
        parties=span(party_start,2048)
        for bit in range(11):
            selected=[party for party,reciprocal in zip(parties,reciprocals) if (reciprocal>>bit)&1]
            if len(selected)!=1024 or parties[-1] in selected:raise ValueError("complete bridge reciprocal plane")
            writer.emit(0,bit_lc(bit_sum(selected+span(slope_start+bit,1))),ONE,ZERO)
        terms=parties+span(target,1)
        if delta is not None:terms+=span(delta,1)
        writer.emit(0,bit_lc(bit_sum(terms)),ONE,ZERO)
        for bit in span(slope_start+11,5):writer.equal_bits(bit,((),0))
    writer.stage("bridge_GF11",start)
    start=writer.snapshot()
    for bit in span(MPLAIN_START+18,6):writer.equal_bits(bit,((),0))
    writer.stage("bridge_M_padding",start)
    start=writer.snapshot()
    bridge_join_rows=[]
    for b in range(20):
        bridge_join_rows.append(writer.rows)
        writer.equal_bits(span(1024+8*bridge_offsets(b)[0],1)[0],span(tape_port(2047+b),1)[0])
    writer.stage("bridge_join",start)

    size = stream.tell()
    if (writer.next, writer.rows, writer.allocs) != (407336, 411697, 269096):
        raise ValueError("exact L14G source shape/allocation")
    if size > MAX_GRAPH_BYTES or writer.rows + PADDED_VARIABLES - writer.next > PADDED_ROWS:
        raise ValueError("graph/padding geometry")
    values = (PUBLIC_BITS, PRIMARY, PRIVATE_BITS, writer.next, writer.rows, writer.nnz, 64, 14)
    stream.seek(0)
    stream.write(HEADER.pack(b"L14G", 1, 0, *values))
    stream.seek(size)
    return dict(zip(("public_bits", "primary", "private_bits", "variables", "rows", "nnz",
                     "field_bits", "case"), values),
                graph_bytes=size, allocated_rows=writer.allocs,
                padded_variables=PADDED_VARIABLES, padded_rows=PADDED_ROWS,
                padded_nnz=writer.nnz + 2 * (PADDED_VARIABLES - writer.next),
                variables_include_constant_one=True, stages=writer.stages,
                source_raw_nnz_upper=3163552, source_padded_nnz_upper=3163984,
                source_graph_bytes_upper=37615391,
                permutations=writer.permutations, rounds=writer.rounds,
                chi_round_nnz=writer.chi_round_nnz, tape_first32_bits=tape_bits[:256], full_tape_bits=tape_bits, shared_D_outputs=writer.shared_D_outputs,
                consistency_first32_bits=points_bits, join_byte_offsets=join_byte_offsets,
                join_row_indices=join_row_indices, coordinate_ports=coordinate_ports,
                inline_theta_by_round=writer.inline_theta_by_round,
                inline_support_counts=writer.inline_support_counts,
                first_multi_chi=writer.first_multi_chi,
                CR_salt_bytes=[50, 98], salt_variables=[SALT_START, SALT_START + 384],
                party0_variable=PARTY_START, prefix_variables=[[PREFIX_START, PREFIX_START + 8],
                                  [PREFIX_EXTRA_START, PREFIX_EXTRA_START + 8],
                                  [PREFIX_THIRD_START, PREFIX_THIRD_START + 8]],
                leaf_seed_variables=[SEED_START, SEED_START + 192],
                tape_prefix_bytes=3, full_tape_bytes=291, valid_tape_bits=2322, canonical_zero_bits=6, joined_prefix_bits=24, seed_tree_origin=False,
                other2047_party_tape_origins=False, full_R2=False, bridge_ports=bridge_ports, bridge_join_rows=bridge_join_rows, bridge_columns=20, bridge_span=[2047,2067], M_polynomials_complete=18, q_qbar_Xi_connected=False)


def _rows(raw, header):
    view, cursor, next_var, nnz = memoryview(raw), HEADER.size, BEGIN, 0
    for row_index in range(header[7]):
        row_offset = cursor
        if cursor >= len(raw):
            raise ValueError("truncated row")
        flag = raw[cursor]
        cursor += 1
        if flag not in (0, 1):
            raise ValueError("row flag")
        lcs = []
        for _ in range(3):
            if cursor + 2 > len(raw):
                raise ValueError("truncated LC count")
            count = ARITY.unpack_from(raw, cursor)[0]
            cursor += 2
            if count > MAX_ARITY or cursor + count * TERM.size > len(raw):
                raise ValueError("LC arity/truncation")
            lc = tuple(TERM.iter_unpack(view[cursor:cursor + count * TERM.size]))
            cursor += count * TERM.size
            previous = -1
            for index, coefficient in lc:
                if index <= previous or index >= next_var or coefficient == 0:
                    raise ValueError("noncanonical/prior-variable LC")
                previous = index
            lcs.append(lc)
        nnz += sum(map(len, lcs)) + flag
        if nnz > MAX_NNZ or flag and next_var >= MAX_VARIABLES:
            raise ValueError("nnz/projection cutoff")
        output = next_var if flag else None
        next_var += flag
        yield row_index, flag, output, tuple(lcs), row_offset
    if cursor != len(raw) or next_var != header[6] or nnz != header[8]:
        raise ValueError("EOF/variables/nnz mismatch")


class ParsedGraph:
    __slots__ = ("raw", "header")

    def __init__(self, raw, header):
        self.raw, self.header = raw, header

    def rows(self):
        return _rows(self.raw, self.header)


def parse(raw):
    if type(raw) is not bytes or not HEADER.size <= len(raw) <= MAX_GRAPH_BYTES:
        raise ValueError("graph byte guard")
    h = HEADER.unpack_from(raw)
    if h[:6] != (b"L14G", 1, 0, PUBLIC_BITS, PRIMARY, PRIVATE_BITS) or h[-2:] != (64, 14):
        raise ValueError("L14G magic/version/ABI")
    if h[6] != MAX_VARIABLES or h[7] != MAX_ROWS or not 1 <= h[8] <= MAX_NNZ:
        raise ValueError("graph shape")
    if h[7] + PADDED_VARIABLES - h[6] > PADDED_ROWS:
        raise ValueError("padding geometry")
    for _ in _rows(raw, h):
        pass
    return ParsedGraph(raw, h)


def _lc_value(lc, values):
    result = 0
    for index, coefficient in lc:
        value = values[index]
        if coefficient == 1:
            result ^= value
        elif value:
            result ^= coefficient if value == 1 else gf_mul(value, coefficient)
    return result


def _execute(parsed, public, private, *, overrides=None, failure_rows=None):
    if type(public) is not bytes or len(public) != 32 or type(private) is not bytes or len(private) != PRIVATE_BYTES:
        raise ValueError("input widths")
    if array("Q").itemsize != 8: raise ValueError("exact GF64 cell8")
    values = array("Q",[0])*MAX_VARIABLES
    values[0]=1
    values[1:257]=array("Q",bits(public))
    values[1024:BEGIN]=array("Q",bits(private))
    next_output=BEGIN
    if overrides is not None:
        for index, value in overrides.items():
            if type(index) is not int or not 1 <= index < BEGIN or type(value) is not int or not 0 <= value < (1 << 64):
                raise ValueError("test override")
            values[index] = value
    failed = 0
    for row_index, flag, output, (a, b, c), row_offset in parsed.rows():
        left, right, constant = (_lc_value(lc, values) for lc in (a, b, c))
        product = gf_mul(left, right)
        if flag:
            if output != next_output:
                raise ValueError("allocation order")
            values[output]=product ^ constant
            next_output+=1
        elif product != constant:
            failed += 1
            if failure_rows is not None:
                failure_rows.append(row_index)
    return failed == 0, values


def evaluate(parsed, public, private, *, overrides=None):
    """Assignment satisfiability only, never cryptographic Verify."""
    return _execute(parsed, public, private, overrides=overrides)[0]


def trace_bytes(parsed, public, private, expressions):
    valid, values = _execute(parsed, public, private)
    if not valid or not 0 < len(expressions) <= 2328:
        raise ValueError("private trace contract")
    out = bytearray((len(expressions)+7) // 8)
    for i, bit in enumerate(expressions):
        value = bit[1]
        for index in bit[0]:
            value ^= values[index]
        if value not in (0, 1):
            raise ValueError("Boolean hash induction")
        out[i // 8] |= value << (i % 8)
    return bytes(out)


def _legacy_private_input(base_LC2, leaf_seed, full_tape, extra_coordinates):
    prefix=full_tape[:3] if type(full_tape) is bytes else None
    if type(full_tape) is not bytes or len(full_tape)!=291: raise ValueError("canonical tape291B")
    if full_tape[-1]&252: raise ValueError("tape high6padding")
    for value, length in ((base_LC2, 5740), (leaf_seed, 24), (prefix, 3), (extra_coordinates, 5934)):
        if type(value) is not bytes or len(value) != length:
            raise ValueError("preserved LC10 body components")
    return (base_LC2 + leaf_seed + prefix[:1] + extra_coordinates[:1806] +
            prefix[1:2] + extra_coordinates[1806:3870] +
            prefix[2:3] + extra_coordinates[3870:] + full_tape[3:])


def bind_legacy_private(CR, P, Mhat, h1, parties, leaf_seed, full_tape):
    if type(parties) not in (list, tuple) or len(parties) != 24:
        raise ValueError("twenty-four party-coordinate arrays")
    if any(type(raw) is not bytes or len(raw) != length
           for raw, length in ((CR, 5074), (P, 256), (Mhat, 32), (h1, 48))):
        raise ValueError("private component widths")
    aggregates = [lc2.aggregate(value) for value in parties]
    corrected = bytearray(3)
    for j, (plain, slope) in enumerate(aggregates):
        corrected[j // 8] |= (plain ^ ((CR[466 + j // 8] >> (j % 8)) & 1)) << (j % 8)
    P = bytes(corrected) + P[3:]
    CR = CR[:146] + lc2.alpha_bytes(P, Mhat, h1) + CR[178:]
    base = lc2.private_input(CR, P, Mhat, h1, P[:72], parties[0],
                            aggregates[0][1].to_bytes(2, "little"))
    extra = b"".join(parties[j] + aggregates[j][1].to_bytes(2, "little") for j in range(1, 24))
    return _legacy_private_input(base, leaf_seed, full_tape, extra)


def reference_legacy_private(random_bytes):
    base = lc2.reference_private(random_bytes)
    CR, P, Mhat, h1 = base[:5074], base[5074:5330], base[5330:5362], base[5362:5410]
    seed = random_bytes(24)
    full_tape = lc3.canonical_tape(CR[50:98], seed)
    prefix = full_tape[:3]
    parties = [base[5482:5738]] + [random_bytes(256) for _ in range(23)]
    parties = [bytes([(value[0] & 254) | ((prefix[j // 8] >> (j % 8)) & 1)]) + value[1:]
               for j, value in enumerate(parties)]
    return bind_legacy_private(CR, P, Mhat, h1, parties, seed, full_tape)


def assertion_failures(parsed, public, private, *, overrides=None):
    """Public row indices only; private data and derived values never logged."""
    failed = []
    _execute(parsed, public, private, overrides=overrides, failure_rows=failed)
    return tuple(failed)


def evaluate_many(parsed, public, privates, *, failure_rows=None, omit_bridge_join_rows_test_only=False):
    """At most26 fixed GF64 vectors; row indices only, never private values."""
    if type(public) is not bytes or len(public)!=32 or type(privates) is not list or not 1<=len(privates)<=26:
        raise ValueError("bounded private batch")
    if type(omit_bridge_join_rows_test_only) is not bool: raise ValueError("exact test-only bool")
    if failure_rows is not None and (type(failure_rows) is not list or len(failure_rows)!=len(privates) or
            any(type(r) is not array or r.typecode!="I" or len(r) for r in failure_rows)):
        raise ValueError("bounded empty packed failures")
    if array("Q").itemsize!=8: raise ValueError("exact GF64 cell8")
    sets=[]
    for private in privates:
        if type(private) is not bytes or len(private)!=PRIVATE_BYTES: raise ValueError("private widths")
        values=array("Q",[0])*MAX_VARIABLES
        values[0]=1
        values[1:257]=array("Q",bits(public))
        values[1024:BEGIN]=array("Q",bits(private))
        sets.append(values)
    failed=[False]*len(sets)
    next_output=BEGIN
    for row,flag,output,lcs,_ in parsed.rows():
        if flag and output!=next_output: raise ValueError("allocation order")
        for i,values in enumerate(sets):
            a,b,c=(_lc_value(lc,values) for lc in lcs)
            product=gf_mul(a,b)
            if flag: values[output]=product^c
            elif product!=c and not (omit_bridge_join_rows_test_only and row>=MAX_ROWS-20):
                failed[i]=True
                if failure_rows is not None:
                    if len(failure_rows[i])>=128: raise ValueError("bounded failure rows")
                    failure_rows[i].append(row)
        if flag: next_output+=1
    if next_output!=MAX_VARIABLES: raise ValueError("complete allocations")
    return tuple(not x for x in failed)


def bind_bridge(base, bridge_parties):
    """Complete2048-party LP coefficients, not free aggregate hints or MPC q."""
    if type(base) is not bytes or len(base)!=11989:raise ValueError("preserved LC12 body11989")
    if type(bridge_parties) not in (list,tuple) or len(bridge_parties)!=20:raise ValueError("bridge20 arrays")
    aggregates=[lc2.aggregate(p) for p in bridge_parties]
    body=bytearray(base)
    body[5329]=(body[5329]&127)|((aggregates[0][0]^((body[721]>>7)&1))<<7)
    body[5330]=(body[5330]&254)|(aggregates[19][0]^(body[722]&1))
    body[146:178]=lc2.alpha_bytes(bytes(body[5074:5330]),bytes(body[5330:5362]),bytes(body[5362:5410]))
    extra=b"".join(p+slope.to_bytes(2,"little") for p,(_,slope) in zip(bridge_parties,aggregates))
    mplain=sum(aggregates[k+1][0]<<k for k in range(18))
    return bytes(body)+extra+mplain.to_bytes(3,"little")

def reference_private(random_bytes):
    base=reference_legacy_private(random_bytes)
    tape=bytes(base[p] for p in (5764,7571,9636))+base[11701:11989]
    parties=[]
    for b in range(20):
        raw=random_bytes(256);j=2047+b
        parties.append(bytes([(raw[0]&254)|((tape[j//8]>>(j%8))&1)])+raw[1:])
    return bind_bridge(base,parties)
