"""Reproducible same-author review experiments, not a verifier or attestation.

Run from the repository root with PYTHONPATH=src:tests. No raw keys, witnesses,
or input packets are printed or written. The bit-mask grammar oracle consumes
the frozen JSON rather than the runtime codec's private schema or encoders.
"""

from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import time

from pq_rbbc.contracts.system import KeyRole
from pq_threshold_candidates import ContractError, Unsupported
from pq_threshold_candidates.gf import keygen_reference_for_test
from pq_threshold_candidates.gf.research_abi_v0_1 import (
    ResearchCommonPP, ResearchIssueStatement, ResearchIssueWitness,
    ResearchTicketM, ResearchTraceBinding, check_key_pp_bindings_research,
    public_key_record_sha256_research,
)
from threshold_candidates.gf.research_abi_v0_1._fixtures import arguments, fixture


ROOT = Path(__file__).resolve().parents[5]
FROZEN_ABI = ROOT / "docs/literature/threshold_backends/gf/abi_v0_1/contract_v0_1.json"
TYPES = dict(trace_binding=ResearchTraceBinding, common_pp=ResearchCommonPP,
             ticket_m=ResearchTicketM, issue_statement=ResearchIssueStatement,
             issue_witness=ResearchIssueWitness)


def sha(raw):
    return hashlib.sha256(raw).digest()


def require(condition, label):
    # Do not use assert: running this review with python -O must still check.
    if not condition:
        raise RuntimeError(label)


class ShapeOracle:
    """Flatten the declarative grammar into fixed-bit masks and nonzero ranges.

    This representation does not decode fields, instantiate packet dataclasses,
    call the CAP serializer, or consult runtime _FIELDS/_MAGIC/_SIZE constants.
    It models canonical bytes only, without a cryptographic validity claim.
    """

    def __init__(self, descriptor, name):
        compact = json.dumps(descriptor, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")
        abi = sha(compact)
        require(abi.hex() == "97e97589fdcb293101e866a3233b38e1f48c9bdbe5ad9ddc1daabe5f2b410158",
                "frozen ABI identity changed")
        self.size = descriptor["layouts"][name]["bytes"]
        self.mask = bytearray(self.size)
        self.fixed = bytearray(self.size)
        self.nonzero = []

        def fix(offset, data):
            self.mask[offset:offset + len(data)] = b"\xff" * len(data)
            self.fixed[offset:offset + len(data)] = data

        def flatten(packet, start):
            for field in descriptor["layouts"][packet]["fields"]:
                offset, width = start + field["offset"], field["bytes"]
                if "nested" in field:
                    flatten(field["nested"], offset)
                elif "literal_hex" in field:
                    fix(offset, bytes.fromhex(field["literal_hex"]))
                elif field.get("derived") == "abi_sha256":
                    fix(offset, abi)
                elif field.get("nonzero"):
                    self.nonzero.append((offset, width))
                elif field.get("external_codec"):
                    require(field["external_codec"] == "pinned_B_legacy_18_tree_CAP_randomness",
                            "unexpected external codec")
                    # Separate derivation from the documented legacy CAP grammar:
                    # 84-byte magic/profile; two field salts; u16 tree count;
                    # 36 field roots. A field element is < 2**193 in 25 LE bytes.
                    prefix = b"PQRBBC-CAP-RANDOM-V1" + descriptor["bridge"]["cap_profile_sha256"].encode("ascii")
                    require(len(prefix) == 84 and width == 1036, "wrong CAP layout")
                    fix(offset, prefix)
                    fix(offset + 134, b"\x12\x00")
                    for relative in (108, 133, *(160 + 25 * i for i in range(36))):
                        self.mask[offset + relative] = 0xfe
        flatten(name, 0)

    def accepts(self, raw):
        return (type(raw) is bytes and len(raw) == self.size
                and all((v & m) == f for v, m, f in zip(raw, self.mask, self.fixed))
                and all(any(raw[start:start + width]) for start, width in self.nonzero))

    def synthetic_bytes(self, name):
        raw = hashlib.shake_256(b"NOT-ATTESTATION/GF-CODEC-REVIEW/" + name.encode()).digest(self.size)
        raw = bytes((v & (m ^ 255)) | f for v, m, f in zip(raw, self.mask, self.fixed))
        require(self.accepts(raw), "oracle fixture must be canonical")
        require(all(int.from_bytes(raw[s:s + w], "little").bit_count() > 1
                    for s, w in self.nonzero), "single-bit sweep nonzero precondition")
        return raw


def decode_agrees(codec, raw, expected):
    try:
        value = codec.decode(raw)
    except ContractError:
        require(not expected, "runtime rejected canonical oracle bytes")
        return False
    require(expected, "runtime accepted noncanonical oracle bytes")
    require(value.encode() == raw, "accepted bytes changed on round-trip")
    return True


def check_packets(descriptor):
    reports = {}
    for name, codec in TYPES.items():
        oracle = ShapeOracle(descriptor, name)
        raw = oracle.synthetic_bytes(name)
        decode_agrees(codec, raw, True)
        accepted = rejected = 0
        for offset in range(len(raw)):
            for bit in range(8):
                changed = raw[:offset] + bytes([raw[offset] ^ (1 << bit)]) + raw[offset + 1:]
                # Every base nonzero range has at least two set bits. Therefore
                # one flip cannot zero it; only the fixed-bit mask can reject.
                want = not (oracle.mask[offset] & (1 << bit))
                if decode_agrees(codec, changed, want):
                    accepted += 1
                else:
                    rejected += 1
        near_zero_accepted = 0
        for start, width in oracle.nonzero:
            zero = raw[:start] + bytes(width) + raw[start + width:]
            decode_agrees(codec, zero, False)
            for bit in range(8 * width):
                changed = zero[:start] + (1 << bit).to_bytes(width, "little") + zero[start + width:]
                require(oracle.accepts(changed), "one-bit nonzero digest must be canonical")
                decode_agrees(codec, changed, True)
                near_zero_accepted += 1
        reports[name] = dict(single_bit_accepted=accepted, single_bit_rejected=rejected,
                             zero_digest_rejected=len(oracle.nonzero),
                             one_bit_digest_accepted=near_zero_accepted)
    return reports


def check_key_coefficients(pk):
    # Repack by one whole little-endian integer, independent of the production
    # streaming bit packer. Canonical shape does not certify KeyGen output.
    header = pk.encode()[:-22528]
    accepted = rejected = 0
    for index in (0, 1, 3, 4, 255, 256, 4095, 4096, 8191):
        for coefficient in (0, 2094080, 4188160, 4188161, (1 << 22) - 1):
            payload = (coefficient << (22 * index)).to_bytes(22528, "little")
            raw = header + payload
            want = coefficient < 4188161
            try:
                actual = public_key_record_sha256_research(raw)
            except ContractError:
                require(not want, "canonical boundary coefficient rejected")
                rejected += 1
            else:
                require(want and actual == sha(raw), "bad coefficient or wrong key hash accepted")
                accepted += 1
    return dict(canonical_accepted=accepted, out_of_range_rejected=rejected)


def alternate_graph(first, other_pk):
    """Construct a second, distinct, unsigned test graph, not a valid relation."""
    keys = tuple(replace(k, key_id=bytes([50 + int(k.role)]) * 32,
                         public_key_digest=sha(other_pk.encode()) if k.role == KeyRole.OPENING_ENCRYPTION
                         else bytes([80 + int(k.role)]) * 32) for k in first.bundle.keys)
    cfg = replace(first.bundle.configuration, epoch=8, domain=b"B" * 32,
                  oa_key_id=keys[4].key_id, issuer_key_id=keys[3].key_id)
    origin, backend, manifest = (b"INSECURE-TEST-ONLY/graph-B/" + n for n in (b"origin", b"backend", b"relation"))
    binding = replace(first.binding, configuration_sha256=sha(cfg.encode()), ctx=cfg.ctx,
                      epoch=cfg.epoch, oa_key_id=cfg.oa_key_id, tpk_record_sha256=sha(other_pk.encode()),
                      issuer_key_id=cfg.issuer_key_id, issuer_public_key_sha256=keys[3].public_key_digest,
                      key_origin_evidence_sha256=sha(origin))
    pp = ResearchCommonPP(binding, sha(backend), sha(manifest))
    bundle = replace(first.bundle, configuration=cfg, common_parameters_digest=pp.sha256, keys=keys)
    return dict(expected_bundle_sha256=sha(bundle.encode()), initialization_bundle=bundle.encode(),
                common_pp=pp.encode(), tpk_record=other_pk.encode(), key_origin_evidence=origin,
                issue_backend_pp=backend, gf_full_relation_manifest=manifest,
                statement=replace(first.statement, common_pp_sha256=pp.sha256, ctx=cfg.ctx).encode(),
                ticket_m=replace(first.m, common_pp_sha256=pp.sha256, ctx=cfg.ctx).encode(), purpose="research")


def check_binding_graph(first, second):
    groups = (("expected_bundle_sha256", "initialization_bundle"), ("common_pp",),
              ("tpk_record",), ("key_origin_evidence",), ("issue_backend_pp",),
              ("gf_full_relation_manifest",), ("statement",), ("ticket_m",))
    for group in groups:
        require(all(first[k] != second[k] for k in group), "graphs must differ in every input group")
    accepted = rejected = production_rejected = 0
    for choices in itertools.product((0, 1), repeat=len(groups)):
        inputs = {k: (first, second)[choice][k] for group, choice in zip(groups, choices) for k in group}
        want = len(set(choices)) == 1
        try:
            result = check_key_pp_bindings_research(**inputs, purpose="research")
        except ContractError:
            require(not want, "self-consistent graph rejected")
            rejected += 1
        else:
            require(want, "mixed graph accepted")
            require(result.authentication_verified is False and result.production_qualified is False,
                    "research diagnostic promoted to qualification")
            accepted += 1
        for purpose in ({}, {"purpose": "production"}):
            try:
                check_key_pp_bindings_research(**inputs, **purpose)
            except Unsupported:
                production_rejected += 1
            else:
                raise RuntimeError("production binding gate succeeded")
    return dict(self_consistent_diagnostics=accepted, mixed_graphs_rejected=rejected,
                default_and_explicit_production_rejected=production_rejected)


def main():
    start = time.perf_counter()
    descriptor = json.loads(FROZEN_ABI.read_text(encoding="utf-8"))
    packets = check_packets(descriptor)
    pk_a, _ = keygen_reference_for_test(sha(b"GF-codec-review-key-A"))
    pk_b, _ = keygen_reference_for_test(sha(b"GF-codec-review-key-B"))
    first = fixture(pk_a, bytes(128))
    report = dict(schema="pqc_auth.gf_codecs_review_experiments.v0_1", packets=packets,
                  key_coefficients=check_key_coefficients(pk_a),
                  binding_graph=check_binding_graph(arguments(first), alternate_graph(first, pk_b)),
                  discrepancies=0, external_independent_review=False,
                  authentication_verified=False, production_qualified=False,
                  elapsed_seconds=round(time.perf_counter() - start, 3))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
