"""Document conformance only: synthetic framing, offsets and digest checks.

Not a runtime codec, trusted identity verifier, encryption fixture, or proof.
Outputs digests/counts only; never writes packets, keys, witnesses or attestations.
"""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load(path):
    def bad_constant(value):
        raise ValueError("non-JSON numeric constant")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                      parse_constant=bad_constant)


def compact(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).digest()


def main():
    contract = load(HERE / "contract_v0_1.json")
    abi = sha(compact(contract))
    layouts = contract["layouts"]
    expected_lengths = {"trace_binding": 315, "ticket_m": 3005, "common_pp": 489,
                        "issue_statement": 251, "issue_witness": 4324}
    if {k: v["bytes"] for k, v in layouts.items()} != expected_lengths:
        raise ValueError("layout arithmetic differs from specification")
    descriptor = load(HERE.parent / "reference_profile_v1.json")
    if sha(compact(descriptor)).hex() != contract["crypto_profile_sha256"]:
        raise ValueError("frozen crypto profile mismatch")
    if sha((HERE.parent / "reference_profile_v1.json").read_bytes()) == sha(compact(descriptor)):
        raise ValueError("file digest and profile fingerprint unexpectedly equal")
    for name, layout in layouts.items():
        offset = 0
        seen = set()
        for field in layout["fields"]:
            if field["name"] in seen or field["offset"] != offset:
                raise ValueError("duplicate field or non-contiguous offsets")
            seen.add(field["name"])
            if type(field["bytes"]) is not int or field["bytes"] <= 0:
                raise ValueError("invalid field size")
            offset += field["bytes"]
            if "nested" in field and field["bytes"] != layouts[field["nested"]]["bytes"]:
                raise ValueError("nested length mismatch")
            if "literal_hex" in field and len(bytes.fromhex(field["literal_hex"])) != field["bytes"]:
                raise ValueError("literal length mismatch")
        if offset != layout["bytes"]:
            raise ValueError("packet length mismatch")

    def assemble(name, supplied=None):
        supplied = supplied or {}
        parts = []
        for field in layouts[name]["fields"]:
            label = field["name"]
            if label in supplied:
                raw = supplied[label]
            elif "literal_hex" in field:
                raw = bytes.fromhex(field["literal_hex"])
            elif field.get("derived") == "abi_sha256":
                raw = abi
            elif "nested" in field:
                raw = assemble(field["nested"])
            else:
                # Publicly specified synthetic shape, not valid crypto material.
                raw = hashlib.shake_256(b"NOT-ATTESTATION/SHAPE-ONLY/" +
                                       name.encode() + b"/" + label.encode()).digest(field["bytes"])
            if len(raw) != field["bytes"]:
                raise ValueError("synthetic field length mismatch")
            parts.append(raw)
        return b"".join(parts)

    def structural_parse(name, raw):
        if type(raw) is not bytes or len(raw) != layouts[name]["bytes"]:
            raise ValueError("wrong structural packet length")
        result = {}
        for field in layouts[name]["fields"]:
            value = raw[field["offset"]:field["offset"] + field["bytes"]]
            if "literal_hex" in field and value != bytes.fromhex(field["literal_hex"]):
                raise ValueError("wrong structural literal")
            if field.get("derived") == "abi_sha256" and value != abi:
                raise ValueError("wrong structural ABI")
            if field.get("nonzero") and value == bytes(field["bytes"]):
                raise ValueError("zero identity field")
            if "nested" in field:
                structural_parse(field["nested"], value)
            result[field["name"]] = value
        # Opaque rho/r/beta/C are intentionally not cryptographically validated.
        return result

    packets = {name: assemble(name) for name in layouts}
    positive, negative = 0, 0
    vectors = {}
    for name, raw in packets.items():
        if assemble(name, structural_parse(name, raw)) != raw:
            raise ValueError("synthetic round trip failed")
        positive += 1
        vectors[name] = {"bytes": len(raw), "sha256": sha(raw).hex()}
        invalid = [raw[:-1], raw + b"\0"]
        for field in layouts[name]["fields"]:
            if "literal_hex" in field or "derived" in field or field.get("nonzero"):
                changed = bytearray(raw)
                start = field["offset"]
                if field.get("nonzero"):
                    changed[start:start + field["bytes"]] = bytes(field["bytes"])
                else:
                    changed[start] ^= 1
                invalid.append(bytes(changed))
        for value in invalid:
            try:
                structural_parse(name, value)
            except ValueError:
                negative += 1
            else:
                raise ValueError("malformed structure accepted")

    # Change just a key digest in synthetic PP; no claim that either PP is trusted.
    binding_a = packets["trace_binding"]
    binding_b = assemble("trace_binding", {"tpk_record_sha256": sha(b"OTHER-NON-KEY-FIXTURE")})
    pp_a = assemble("common_pp", {"trace_binding": binding_a})
    pp_b = assemble("common_pp", {"trace_binding": binding_b})
    m_a = assemble("ticket_m", {"common_pp_sha256": sha(pp_a)})
    m_b = assemble("ticket_m", {"common_pp_sha256": sha(pp_b)})
    digest = lambda raw: hashlib.shake_256(b"PQ-RBBC/TICKET" + raw).digest(32)
    if structural_parse("ticket_m", m_a)["ciphertext_payload"] != structural_parse("ticket_m", m_b)["ciphertext_payload"]:
        raise ValueError("fixture must preserve identical raw C")
    if m_a == m_b or digest(m_a) == digest(m_b):
        raise ValueError("PP header did not affect M/d_M")
    if digest(m_a) == digest(m_a[77:]):
        raise ValueError("full-M and header-free digest fixture collision")
    expected = set(contract["partition"]["public_semantic"])
    if expected != {"pp", "ctx", "sid", "rid", "beta"}:
        raise ValueError("public semantic partition drift")
    if not contract["raw_trace_witness_slot"]["zero_witness_allowed"]:
        raise ValueError("zero witness silently excluded")
    if any(v for k, v in contract["claims"].items() if k != "candidate_bytes_defined"):
        raise ValueError("specification claims exceeded")
    print(json.dumps({
        "schema": "pqc_auth.gf_binding_abi_document_check.v0_1",
        "abi_sha256": abi.hex(), "structural_round_trips": positive,
        "structural_negative_cases_rejected": negative, "failed": 0,
        "synthetic_shape_digests": vectors,
        "same_C_different_pp_produces_different_M_and_d_M": True,
        "full_M_and_header_free_digest_differ": True,
        "limitations": ["Synthetic packets are not valid encryption/relation fixtures.",
                        "No trusted binding, signature, key-origin, CAP or proof validation.",
                        "Only document conformance; no runtime codec or owner acceptance."]
    }, indent=2))


if __name__ == "__main__":
    main()
