#!/usr/bin/env python3
"""V2.42 bounded recovery successor; no production executor or launch authoring.

Only the exact v2.36/v2.37 40-leaf fixtures can be materialized. V2.38 files are
never resumed in place: a new output and versioned contract are required.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

import pq_rbbc_cap_unified_tree_streaming_prefreeze as old
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifests/pq_rbbc_cap_unified_tree_recovery_manifest_v2_42.json"
MANIFEST_SHA256 = "bba9b8c4aa00069896a2d067ea1f6cd130015639a3598265927a702585ad8f98"
PROVENANCE_PATH = ROOT / "manifests/pq_rbbc_cap_unified_tree_provenance_v2_42.json"
CHUNK_DIRECTORY = "chunks"
JOURNAL_DIRECTORY = "checkpoints"
COMPLETE_FILENAME = "complete-v2_42.json"
INDEX_FILENAME = "stream-index-v2_42.json"
EVIDENCE_FILENAME = "bounded-evidence-v2_42.json"
VERSION = "2.42"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(name, raw):
    return io.Snapshot(Path(name), raw).identity


def claim_boundary():
    return {key: False for key in (
        "production_stream_materialized", "production_runner_scale_qualified",
        "production_prefreeze_authorized", "production_prefreeze_started",
        "large_replay_started", "large_proving_run_started", "production_closed",
        "cap_security_qualified", "fork_security_proof_revalidated",
        "qrom_qualified", "launch_manifest_frozen", "independent_review_frozen",
        "operator_resource_reservation_frozen", "v2_41_reservation_authorizes_v2_42",
    )}


def contract_snapshots():
    snapshot = io.read_snapshot(MANIFEST_PATH)
    if snapshot.identity["sha256"] != MANIFEST_SHA256:
        raise io.ValidationError("v2.42 tracked recovery contract identity")
    manifest = snapshot.document()
    for relative, expected in manifest["tracked_predecessors"].items():
        captured = io.read_snapshot(ROOT / relative)
        if captured.identity != expected:
            raise io.ValidationError("historical predecessor identity: " + relative)
    provenance = io.read_snapshot(PROVENANCE_PATH)
    if provenance.identity != manifest["provenance_identity"]:
        raise io.ValidationError("v2.42 provenance identity")
    provenance.document()
    return snapshot, provenance


def validate_contracts():
    return contract_snapshots()[0]


def bounded_chunks(checkpoint_input: io.Snapshot, parent_input: io.Snapshot):
    """Reconstruct expected chunks solely from identity-checked input snapshots."""
    if checkpoint_input.identity != old.V2_36_CHECKPOINT_IDENTITY:
        raise io.ValidationError("exact v2.36 bounded fixture required")
    if parent_input.identity != old.V2_37_BOUNDED_VECTOR_IDENTITY:
        raise io.ValidationError("exact v2.37 bounded fixture required")
    # These exact historical fixtures contain floating-point timing observations.
    # Parse ONLY after the size/SHA-256 allowlist check above. New recovery JSON
    # always uses the strict integer-only v2.41 parser.
    checkpoint = json.loads(checkpoint_input.raw.decode("utf-8", errors="strict"))
    old.v2_36.validate_checkpoint_document(
        checkpoint, old.v2_36.state_contract(old.v2_36.MANIFEST_PATH))
    execution, _ = old.v2_36._decode_tree_snapshot(
        old.v2_36._stage_data(checkpoint, "unified-tree"))
    c_r = execution.commitment.encode()
    vector = json.loads(parent_input.raw.decode("utf-8", errors="strict"))
    old.abi.validate_bounded_vector(vector, c_r)
    parent_bytes = bytes.fromhex(vector["parent_input_hex"])
    parent = old.abi.UnifiedParentInput.decode(
        parent_bytes, expected_profile_fingerprint=old.BOUNDED_PROFILE_FINGERPRINT)
    old.abi.validate_bounded_parent_mapping(parent, c_r)
    records = []
    groups = (
        ("tree-nodes", execution.nodes, old.unified._field_bytes),
        ("leaf-commitments", execution.leaf_commitments, old.unified._hash_bytes),
        ("leaf-tapes", execution.leaf_tapes,
         lambda x: x.to_bytes((execution.parameters.tape_bits + 7) // 8, "little")),
        ("logical-vector-hashes", execution.vector_hashes, old.unified._hash_bytes),
        ("unified-commitment", (c_r,), bytes),
        ("parent-input", (parent_bytes,), bytes),
    )
    for stage, values, encode in groups:
        records.extend(old.StreamRecord(stage, i, encode(value))
                       for i, value in enumerate(values))
    if len(records) != 179:
        raise io.ValidationError("bounded record count")
    return old.make_chunks(records, old.BOUNDED_RECORDS_PER_CHUNK)


def prefix_name(count):
    return f"{count:04d}-prefix-v2_42.json"


def expected_documents(manifest, inputs, chunks):
    """Pure expected state: no observed chunk can define its own commitment."""
    implementation = {name: io.read_snapshot(ROOT / "src" / name).identity for name in (
        "pq_rbbc_cap_unified_tree_recovery_v2_42.py", "pq_rbbc_recovery_io_v2_42.py")}
    contract = {"manifest": manifest.identity, "implementation": implementation,
                "inputs": [item.identity for item in inputs],
                "profile_fingerprint": old.BOUNDED_PROFILE_FINGERPRINT,
                "production_profile_permitted": False}
    prefixes = []
    records = []
    chain = digest(io.canonical_json({"contract": contract}))
    for count in range(len(chunks) + 1):
        if count:
            chunk = chunks[count - 1]
            raw = chunk.encode(old.BOUNDED_PROFILE_FINGERPRINT)
            record = {"ordinal": chunk.ordinal, "stage": chunk.stage,
                      "first_item_index": chunk.first_item_index,
                      "record_count": len(chunk.records),
                      "chunk_identity": identity(old.chunk_filename(chunk), raw),
                      "prior_chain_sha256": chain}
            chain = digest(io.canonical_json(record))
            records.append({**record, "chain_sha256": chain})
        prefixes.append({
            "format": "PQRBBC-CAP-BOUNDED-RECOVERY-CHECKPOINT-2",
            "implementation_version": VERSION, "contract": contract,
            "completed_chunk_count": count, "chunk_records": list(records),
            "chain_sha256": chain, "complete": False,
            "previous_checkpoint_sha256": digest(io.canonical_json(prefixes[-1]))
            if prefixes else None,
            "production_records_materialized": 0,
            "production_relation_rows_replayed": 0,
        })
    complete = {**prefixes[-1], "complete": True,
                "previous_checkpoint_sha256": digest(io.canonical_json(prefixes[-1]))}
    index = {
        "format": "PQRBBC-CAP-BOUNDED-RECOVERY-INDEX-2", "implementation_version": VERSION,
        "checkpoint": identity(COMPLETE_FILENAME, io.canonical_json(complete)),
        "chunk_identities": [r["chunk_identity"] for r in records],
        "chunk_identity_stream_sha256": digest(b"".join(
            bytes.fromhex(r["chunk_identity"]["sha256"]) for r in records)),
        "bounded_records_materialized": 179, "bounded_chunks_materialized": len(chunks),
        "production_records_materialized": 0, "production_relation_rows_replayed": 0,
    }
    evidence = {"format": "PQRBBC-CAP-BOUNDED-RECOVERY-EVIDENCE-2",
                "implementation_version": VERSION, "contract": contract,
                "checkpoint": index["checkpoint"],
                "index": identity(INDEX_FILENAME, io.canonical_json(index)),
                "bounded_records_materialized": 179, "bounded_chunks_materialized": len(chunks),
                "production_leaves_expanded": 0, "proofs_generated": 0,
                "claim_boundary": claim_boundary()}
    return prefixes, complete, index, evidence


def _names(path):
    with io.directory_fd(path, external=True) as fd:
        names = set(os.listdir(fd))
        io._same_directory(path, fd, external=True)
    return names


def _require_document(path, expected):
    captured = disk.read(path)
    captured.document()  # strict JSON (including exact int/bool encoding)
    if captured.raw != io.canonical_json(expected):
        raise io.ValidationError("checkpoint/index exact bytes mismatch: " + path.name)
    return captured


def _require_chunk(path, expected):
    captured = disk.read(path)
    raw = expected.encode(old.BOUNDED_PROFILE_FINGERPRINT)
    decoded = old.StreamChunk.decode(captured.raw, old.BOUNDED_PROFILE_FINGERPRINT,
                                     old.bounded_layout()["stage_payload_bytes"][expected.stage])
    if (captured.raw != raw or captured.identity != identity(path.name, raw)
            or decoded.ordinal != expected.ordinal or decoded.stage != expected.stage
            or decoded != expected):
        raise io.ValidationError("chunk differs from recomputed bytes/sha256/ordinal/stage")
    return captured


def latest_checkpoint(output: Path, *, artifact_root: Path):
    """Inventory helper only; caller must independently trust the supplied digest.

    This returns captured bytes, not a validation/authorization decision. Resume
    checks the digest AND recomputes the entire journal and chunk prefix.
    """
    root = io.ArtifactRoot(artifact_root)
    root.require_location(output / JOURNAL_DIRECTORY / COMPLETE_FILENAME)
    names = _names(output / JOURNAL_DIRECTORY)
    allowed = {prefix_name(i) for i in range(16)} | {COMPLETE_FILENAME}
    if not names or names - allowed:
        raise io.ValidationError("unknown or empty checkpoint journal")
    name = COMPLETE_FILENAME if COMPLETE_FILENAME in names else max(names)
    return disk.read(output / JOURNAL_DIRECTORY / name)


def run_bounded_stream(checkpoint_input_path, parent_input_path, output, *,
                       artifact_root, input_root, fresh_output=False, resume=False,
                       expected_checkpoint_sha256=None, stop_after_chunks=None):
    if type(fresh_output) is not bool or type(resume) is not bool or fresh_output == resume:
        raise io.ValidationError("select exactly one fresh-output or resume")
    if fresh_output and expected_checkpoint_sha256 is not None:
        raise io.ValidationError("fresh-output forbids checkpoint digest")
    if resume and (type(expected_checkpoint_sha256) is not str
                   or len(expected_checkpoint_sha256) != 64
                   or any(c not in "0123456789abcdef" for c in expected_checkpoint_sha256)):
        raise io.ValidationError("resume requires external expected checkpoint SHA-256")
    manifest = validate_contracts()
    source = io.ArtifactRoot(input_root)
    inputs = (source.read(checkpoint_input_path), source.read(parent_input_path))
    chunks = bounded_chunks(*inputs)
    prefixes, complete, index, evidence = expected_documents(manifest, inputs, chunks)
    target = len(chunks) if stop_after_chunks is None else stop_after_chunks
    if type(target) is not int or not 0 <= target <= len(chunks):
        raise io.ValidationError("invalid stop-after-chunks")
    with disk.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        if fresh_output:
            for name in (CHUNK_DIRECTORY, JOURNAL_DIRECTORY):
                os.mkdir(name, mode=0o700, dir_fd=output_fd)
            os.fsync(output_fd)
            disk.publish(output / JOURNAL_DIRECTORY / prefix_name(0), io.canonical_json(prefixes[0]))
        return _recover(output, chunks, prefixes, complete, index, evidence, target,
                        expected_checkpoint_sha256 if resume else None)


def _recover(output, chunks, prefixes, complete, index, evidence, target, expected_sha256):
    allowed = {CHUNK_DIRECTORY, JOURNAL_DIRECTORY, INDEX_FILENAME, EVIDENCE_FILENAME}
    if _names(output) - allowed:
        raise io.ValidationError("unknown output artifact")
    journal = output / JOURNAL_DIRECTORY
    names = _names(journal)
    expected_names = [prefix_name(i) for i in range(len(prefixes))]
    if names - set(expected_names) - {COMPLETE_FILENAME}:
        raise io.ValidationError("unknown checkpoint artifact")
    committed = [name for name in expected_names if name in names]
    if not committed or committed != expected_names[:len(committed)]:
        raise io.ValidationError("checkpoint journal is not a contiguous prefix")
    count = len(committed) - 1
    last = None
    for i, name in enumerate(committed):
        last = _require_document(journal / name, prefixes[i])
    finished = COMPLETE_FILENAME in names
    if finished:
        if count != len(chunks):
            raise io.ValidationError("premature complete checkpoint")
        last = _require_document(journal / COMPLETE_FILENAME, complete)
    if expected_sha256 is not None and last.identity["sha256"] != expected_sha256:
        raise io.ValidationError("resume checkpoint identity mismatch (including stale digest)")
    if target < count:
        raise io.ValidationError("stop boundary precedes committed prefix")
    chunk_names = _names(output / CHUNK_DIRECTORY)
    ordered = [old.chunk_filename(c) for c in chunks]
    required = set(ordered[:count])
    # A sequential writer can leave at most its next chunk orphaned.
    allowed_chunks = set(ordered[:min(count + 1, len(chunks))])
    if not required <= chunk_names or chunk_names - allowed_chunks:
        raise io.ValidationError("unknown, missing, gapped or multiple orphan chunks")
    for chunk in chunks[:min(count + 1, len(chunks))]:
        if old.chunk_filename(chunk) in chunk_names:
            _require_chunk(output / CHUNK_DIRECTORY / old.chunk_filename(chunk), chunk)
    finals = ((INDEX_FILENAME, index), (EVIDENCE_FILENAME, evidence))
    present = _names(output)
    for name, document in finals:
        if name in present:
            if not finished or (name == EVIDENCE_FILENAME and INDEX_FILENAME not in present):
                raise io.ValidationError("premature final artifact")
            _require_document(output / name, document)
    # No mutation until ALL existing durable state (including an orphan) passes.
    for chunk in chunks[count:target]:
        path = output / CHUNK_DIRECTORY / old.chunk_filename(chunk)
        if path.name not in chunk_names:
            disk.publish(path, chunk.encode(old.BOUNDED_PROFILE_FINGERPRINT))
        # Recheck the exact bytes that will be adopted immediately before commit.
        _require_chunk(path, chunk)
        disk.publish(journal / prefix_name(chunk.ordinal + 1),
                     io.canonical_json(prefixes[chunk.ordinal + 1]))
    if target < len(chunks):
        return None
    # Revalidate the completed durable set before finalization. This detects
    # observed interference; it is not a proof of filesystem immutability.
    if _names(output / CHUNK_DIRECTORY) != set(ordered):
        raise io.ValidationError("completed chunk inventory changed")
    for chunk in chunks:
        _require_chunk(output / CHUNK_DIRECTORY / old.chunk_filename(chunk), chunk)
    if not finished:
        disk.publish(journal / COMPLETE_FILENAME, io.canonical_json(complete))
    for name, document in finals:
        if name not in present:
            disk.publish(output / name, io.canonical_json(document))
    return evidence


def reject_production_prefreeze(*args, **kwargs):
    raise io.ValidationError("v2.42 production-prefreeze unavailable; no reservation or review authorizes execution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("bounded", "production-prefreeze"), required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--input-root", type=Path)
    parser.add_argument("--checkpoint-payload", type=Path)
    parser.add_argument("--bounded-parent-vector", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--fresh-output", action="store_true")
    choice.add_argument("--resume", action="store_true")
    parser.add_argument("--expected-checkpoint-sha256")
    parser.add_argument("--stop-after-chunks", type=int)
    args = parser.parse_args()
    if args.phase == "production-prefreeze":
        reject_production_prefreeze()
    if any(value is None for value in (args.input_root, args.checkpoint_payload, args.bounded_parent_vector)):
        parser.error("bounded phase requires input root, checkpoint payload and parent vector")
    result = run_bounded_stream(args.checkpoint_payload, args.bounded_parent_vector,
                               args.output, artifact_root=args.artifact_root,
                               input_root=args.input_root, fresh_output=args.fresh_output,
                               resume=args.resume, expected_checkpoint_sha256=args.expected_checkpoint_sha256,
                               stop_after_chunks=args.stop_after_chunks)
    print(io.canonical_json({"complete": result is not None, "claim_boundary": claim_boundary()}).decode(), end="")


if __name__ == "__main__":
    main()
