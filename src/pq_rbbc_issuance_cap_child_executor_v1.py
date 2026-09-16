#!/usr/bin/env python3
"""Fresh-namespace staged executor contract for the issuance CAP child.

The production plan is definition-only: it freezes a new relation namespace,
the split tree-pre/global-A/tree-post/global-B dependency order, per-tree output
identity requirements, and JSON-only cache/resume binding.  Production always
refuses before output or CAP construction because external inputs, independent
review, runner qualification, and large-run authorization are absent.

The bounded qualification executes one real four-leaf CAP576/1472 native shard
from the first salt/root pair of the exact formal 1,036-byte rho snapshot.  Its
state is an in-memory canonical JSON checkpoint used only to test interruption,
resume, mutation rejection, and deterministic evidence.  No assignment, row
archive, BR1CS, pickle, cache directory, or proof is written by this module.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_production_namespace as legacy_namespace
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_issuance_cap576_native_preflight_v1 as predecessor
import pq_rbbc_issuance_production_inputs_v1 as production_inputs
import pq_rbbc_issuance_relation_v1 as issuance_relation
import pq_rbbc_issuance_zk_backend_preflight as backend
import pq_rbbc_launch_io_v2_41 as launch_io
import pq_rbbc_reference as reference


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-CAP-CHILD-EXECUTOR-PREFLIGHT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-CAP-CHILD-EXECUTOR-PORTABLE-EVIDENCE-1"
STATE_FORMAT = "PQRBBC-ISSUANCE-CAP-CHILD-EXECUTOR-STATE-1"
OUTPUT_IDENTITY_FORMAT = "PQRBBC-ISSUANCE-CAP-CHILD-STAGE-OUTPUT-IDENTITY-1"
PRODUCTION_RELATION_ID = "pq-rbbc/issuance/cap576-native/production-child/candidate/v1"
BOUNDED_RELATION_ID = "pq-rbbc/issuance/cap576-native/staged-4leaf-insecure-test-only/v1"
ROOT = Path(__file__).resolve().parents[1]

DOMAIN_PLAN = b"PQ-RBBC/ISSUANCE-CAP-CHILD/PRODUCTION-PLAN/V1"
DOMAIN_INVOCATION = b"PQ-RBBC/ISSUANCE-CAP-CHILD/INVOCATION/V1"
DOMAIN_CACHE = b"PQ-RBBC/ISSUANCE-CAP-CHILD/CACHE/V1"
DOMAIN_CHAIN = b"PQ-RBBC/ISSUANCE-CAP-CHILD/STATE-CHAIN/V1"
DOMAIN_RESULT = b"PQ-RBBC/ISSUANCE-CAP-CHILD/RESULT/V1"

PRODUCTION_PROFILE = cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS)
BOUNDED_PARAMETERS = predecessor.BOUNDED_CAP576_PARAMETERS
BOUNDED_PROFILE = cap.profile_fingerprint(BOUNDED_PARAMETERS)
PRODUCTION_STAGE_ORDER = (
    "validate-snapshots",
    "bind-invocation",
    *(f"tree-pre[{index}]" for index in range(18)),
    "global-tail-phase-a",
    *(f"tree-post[{index}]" for index in range(18)),
    "global-tail-phase-b",
    "parent-native-join",
    "final-seal",
)
BOUNDED_STAGE_ORDER = (
    "bind-invocation",
    "native-shard",
    "bind-child-outputs",
    "final-seal",
)

FROZEN_PRODUCTION_PLAN_SHA256 = (
    "ececfbf8421dc6593498bf0da8d5b1f9aed61ceee041ca7af0ebf19f594c0943"
)
FROZEN_BOUNDED_STATE_SHA256 = (
    "21c9e3bc39a89597d0d94f6f40df9f0d97383bcb786b5fad0257d857884acf39"
)
FROZEN_BOUNDED_RESULT_SHA256 = (
    "be70c9779a1d1c8e1250f0edab33ab09b30617fcced3888f061aaa0492717ff0"
)
FROZEN_BOUNDED_OUTPUT_IDENTITY_SHA256 = (
    "198c21f9f609341e361bb62896b81efbbba3d0407f8fac42c4ce9fe5cd8384c4"
)


TRACKED_PREREQUISITES = {
    "cap576_preflight_source": (
        "src/pq_rbbc_issuance_cap576_native_preflight_v1.py",
        30_536,
        "19da6b2cbc5e03e6d34c5c6da4910af7391fdef20a3abe981fbbabb6f10dee06",
    ),
    "cap576_preflight_manifest": (
        "manifests/pq_rbbc_issuance_cap576_native_preflight_manifest_v1.json",
        11_704,
        "719dafa600716f53cd81b410c28b40e0d50c6921397dad4dbe7699f5f9480394",
    ),
    "cap576_preflight_evidence": (
        "artifacts/metadata/issuance_cap576_native_preflight_v1/"
        "pq_rbbc_issuance_cap576_native_preflight_portable_evidence_v1.json",
        1_747,
        "c4d6b83b7bc9bd893617761c2424f5551acdcfa6229e778175a03304740caf9f",
    ),
    "legacy_namespace_source": (
        "src/pq_rbbc_cap_production_namespace.py",
        26_130,
        "292a6df8458581a2b00ac5d4f5d7b3fba5ef5cbf88cf3c73fac9a72347a76a27",
    ),
    "legacy_namespace_manifest": (
        "manifests/pq_rbbc_cap_production_namespace_manifest_v2_16.json",
        46_870,
        "1429903c9f94c4fd52902d7946eeb34dd580dce39f390b6c8c94f7e463ef110d",
    ),
    "split_tail_source": (
        "src/pq_rbbc_cap_production_split_tail.py",
        28_610,
        "bd1e48914e81bb021f00f8fb63710395995a54c5595beb9a5d5043008190c7ef",
    ),
    "tree_producer_source": (
        "src/pq_rbbc_cap_tree_producer.py",
        41_039,
        "99ec305af6fa5270ddf9e00ddc3fdaa6276662db15a1ae1a76b02ab790ad14a4",
    ),
    "snapshot_io_source": (
        "src/pq_rbbc_launch_io_v2_41.py",
        10_564,
        "d7589d22abf251f9d2297455bafccaed34be7900b9e11e68ac037d9ad4c3a061",
    ),
    "issuance_relation_source": (
        "src/pq_rbbc_issuance_relation_v1.py",
        31_165,
        "4c0db79e896824c77ef869fdfa2c8fc3e26c9942e12c0a49526f2b54bfbbf57e",
    ),
    "issuance_backend_abi_source": (
        "src/pq_rbbc_issuance_zk_backend_preflight.py",
        47_151,
        "00c0119596983b94bdfd1dcaffe58f0c2f847ca0092c5c53d8f073285092e836",
    ),
}


class ChildExecutorError(ValueError):
    """A staged-executor input, state, or identity is invalid."""


class ProductionChildExecutorUnavailable(RuntimeError):
    """Production execution was requested before its gates are closed."""


def canonical_json(document: object) -> bytes:
    return launch_io.canonical_json(document)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _is_sha256(value: object) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _exact_keys(document: object, expected: set[str], label: str) -> Mapping[str, object]:
    if type(document) is not dict or set(document) != expected:
        raise ChildExecutorError(f"{label} fields are not closed-world canonical")
    return document


def _hash_tuple(domain: bytes, values: Sequence[bytes]) -> str:
    digest = hashlib.sha256(domain)
    for value in values:
        digest.update(len(value).to_bytes(8, "little"))
        digest.update(value)
    return digest.hexdigest()


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures = []
    for name, (relative, expected_bytes, expected_sha256) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
            continue
        if path.stat().st_size != expected_bytes:
            failures.append(f"{name}:bytes")
        if _sha256_file(path) != expected_sha256:
            failures.append(f"{name}:sha256")
    return tuple(failures)


def _rho_root_ranges(tree_index: int) -> tuple[dict[str, int | str], ...]:
    if not 0 <= tree_index < cap.PRODUCTION_PARAMETERS.tree_count:
        raise ChildExecutorError("tree index outside production profile")
    layout = {item["field"]: item for item in predecessor.production_rho_layout()}
    return tuple(
        {
            "field": f"root[{tree_index}][{side}]",
            "byte_start": int(layout[f"root[{tree_index}][{side}]"]["byte_start"]),
            "byte_end_exclusive": int(
                layout[f"root[{tree_index}][{side}]"]["byte_end_exclusive"]
            ),
        }
        for side in (0, 1)
    )


def production_tree_contracts() -> tuple[dict[str, object], ...]:
    plan = legacy_namespace.build_plan()
    contracts = []
    for tree in plan.trees:
        outputs = tuple(
            {
                "port_id": output.port_id,
                "phase": output.phase,
                "planned_wire_start": output.planned_wire_start,
                "planned_wire_end": output.planned_wire_end,
                "consumer_wire_start": output.consumer_wire_start,
                "consumer_wire_end": output.consumer_wire_end,
                "bit_length": output.bit_length,
                "fresh_value_sha256": None,
            }
            for output in tree.outputs
        )
        contracts.append(
            {
                "tree_index": tree.tree_index,
                "fresh_relation_id": (
                    "pq-rbbc/issuance/cap576-native/production-child/"
                    f"tree-{tree.tree_index}/v1"
                ),
                "leaves": tree.leaves,
                "extension_degree": tree.extension_degree,
                "planned_local_wire_start": tree.planned_wire_start,
                "planned_local_wire_end": tree.planned_wire_end,
                "planned_rows": tree.producer_rows,
                "rho_salt_byte_interval": [84, 134],
                "rho_root_byte_intervals": list(_rho_root_ranges(tree.tree_index)),
                "outputs": list(outputs),
                "observed_row_stream_bytes": None,
                "observed_row_stream_sha256": None,
                "assignment_identity": None,
                "historical_value_digest_reused": False,
                "historical_assignment_reused": False,
            }
        )
    return tuple(contracts)


def build_production_execution_plan() -> dict[str, object]:
    legacy = legacy_namespace.build_plan()
    stages = []
    for ordinal, stage_id in enumerate(PRODUCTION_STAGE_ORDER):
        if stage_id.startswith("tree-pre"):
            kind = "tree-pre"
        elif stage_id.startswith("tree-post"):
            kind = "tree-post"
        elif stage_id.startswith("global-tail"):
            kind = "global-tail"
        else:
            kind = stage_id
        stages.append(
            {
                "ordinal": ordinal,
                "stage_id": stage_id,
                "kind": kind,
                "depends_on": [] if ordinal == 0 else [PRODUCTION_STAGE_ORDER[ordinal - 1]],
                "observed_identity": None,
            }
        )
    return {
        "format": "PQRBBC-ISSUANCE-CAP-CHILD-PRODUCTION-PLAN-1",
        "relation_id": PRODUCTION_RELATION_ID,
        "profile_fingerprint": PRODUCTION_PROFILE,
        "legacy_namespace_plan_sha256": legacy_namespace.plan_sha256(legacy),
        "legacy_namespace_relation_id": legacy.relation_id,
        "stage_order": list(PRODUCTION_STAGE_ORDER),
        "stages": stages,
        "tree_contracts": list(production_tree_contracts()),
        "dependency_reason": (
            "all tree-pre outputs feed global-tail phase A; its two consistency "
            "points feed all tree-post stages; phase B then emits commitment, "
            "mask, append base, and request hash before the parent join"
        ),
        "legacy_monolithic_tree_runner_directly_usable": False,
        "fresh_split_pre_post_executor_required": True,
        "historical_assignment_or_values_reused": False,
        "other_tree_observed_stream_bytes_used": False,
        "production_execution_started": False,
    }


def production_plan_sha256() -> str:
    return _sha256(DOMAIN_PLAN + canonical_json(build_production_execution_plan()))


def validate_production_plan() -> tuple[str, ...]:
    failures: list[str] = []
    document = build_production_execution_plan()
    contracts = document["tree_contracts"]
    if len(PRODUCTION_STAGE_ORDER) != 42:
        failures.append("stage_count")
    if len(set(PRODUCTION_STAGE_ORDER)) != len(PRODUCTION_STAGE_ORDER):
        failures.append("stage_duplicate")
    if len(contracts) != 18:
        failures.append("tree_count")
    if document["legacy_namespace_plan_sha256"] != legacy_namespace.FROZEN_PLAN_SHA256:
        failures.append("legacy_plan_identity")
    for expected_index, contract in enumerate(contracts):
        if contract["tree_index"] != expected_index:
            failures.append(f"tree_order:{expected_index}")
        if len(contract["outputs"]) != 4:
            failures.append(f"output_count:{expected_index}")
        if any(output["fresh_value_sha256"] is not None for output in contract["outputs"]):
            failures.append(f"historical_value:{expected_index}")
        if contract["observed_row_stream_bytes"] is not None:
            failures.append(f"observed_stream_bytes:{expected_index}")
        if contract["assignment_identity"] is not None:
            failures.append(f"assignment_identity:{expected_index}")
    if FROZEN_PRODUCTION_PLAN_SHA256 and production_plan_sha256() != FROZEN_PRODUCTION_PLAN_SHA256:
        failures.append("production_plan_sha256")
    return tuple(failures)


@dataclass(frozen=True)
class InvocationSnapshotV1:
    """Immutable formal statement/witness bytes and derived CAP-child inputs."""

    statement_raw: bytes
    witness_raw: bytes
    statement: backend.IssueStatementV1
    witness: backend.IssueWitnessV1
    rho: predecessor.RhoSnapshotV1
    ticket_message: bytes
    invocation_sha256: str


def capture_invocation(statement_raw: bytes, witness_raw: bytes) -> InvocationSnapshotV1:
    if type(statement_raw) is not bytes or type(witness_raw) is not bytes:
        raise ChildExecutorError("invocation requires immutable bytes")
    statement_bytes = memoryview(statement_raw).tobytes()
    witness_bytes = memoryview(witness_raw).tobytes()
    try:
        statement = backend.IssueStatementV1.decode(statement_bytes)
        witness = backend.IssueWitnessV1.decode(witness_bytes)
        payload = issuance_relation.decode_ticket_payload(witness.ticket_payload)
        rho = predecessor.capture_production_rho(witness.cap_randomness)
    except (
        backend.CanonicalEncodingError,
        issuance_relation.IssuanceRelationError,
        predecessor.NativePreflightError,
    ) as error:
        raise ChildExecutorError(str(error)) from error
    if statement.abi_profile_digest != backend.ABI_PROFILE_DIGEST:
        raise ChildExecutorError("wrong statement ABI profile")
    if witness.abi_profile_digest != backend.ABI_PROFILE_DIGEST:
        raise ChildExecutorError("wrong witness ABI profile")
    if payload.ctx != statement.ctx:
        raise ChildExecutorError("ticket payload context does not match statement")
    message = hashlib.shake_256(reference.LABEL_TICKET + witness.ticket_payload).digest(32)
    invocation_sha256 = _hash_tuple(
        DOMAIN_INVOCATION,
        (
            statement_bytes,
            witness.ticket_payload,
            witness.blind_mask,
            rho.raw,
            message,
        ),
    )
    return InvocationSnapshotV1(
        statement_raw=statement_bytes,
        witness_raw=witness_bytes,
        statement=statement,
        witness=witness,
        rho=rho,
        ticket_message=message,
        invocation_sha256=invocation_sha256,
    )


def _candidate_identity_document(
    candidates: production_inputs.CandidateSet,
) -> dict[str, object]:
    return {
        production_inputs.TRACE_KEY_FILENAME: (
            None if candidates.trace_key is None else candidates.trace_key.identity
        ),
        production_inputs.TRACE_CERTIFICATION_FILENAME: (
            None
            if candidates.trace_certification is None
            else candidates.trace_certification.identity
        ),
        production_inputs.INITIALIZATION_FILENAME: (
            None if candidates.initialization is None else candidates.initialization.identity
        ),
        production_inputs.COMMON_PARAMETERS_FILENAME: (
            None
            if candidates.common_parameters is None
            else candidates.common_parameters.identity
        ),
        production_inputs.INDEPENDENT_REVIEW_FILENAME: (
            None
            if candidates.independent_review is None
            else candidates.independent_review.identity
        ),
    }


def production_invocation_preflight(
    candidates: production_inputs.CandidateSet,
    invocation: InvocationSnapshotV1,
) -> dict[str, object]:
    """Evaluate only the supplied snapshots; never reopen their pathnames."""

    candidate_report = production_inputs.evaluate_candidate_set(candidates)
    binding_failures: list[str] = []
    if candidates.common_parameters is None:
        binding_failures.append("common parameters snapshot missing")
    elif invocation.statement.public_parameters_digest != hashlib.sha256(
        candidates.common_parameters.raw
    ).digest():
        binding_failures.append("statement pp does not bind common parameters snapshot")
    blockers = list(candidate_report["blockers"])
    blockers.extend(binding_failures)
    blockers.extend(
        (
            "fresh split tree-pre/tree-post production executor not implemented",
            "production output publisher and resume durability not qualified",
            "qualified PQ simulation-extractable backend not integrated",
            "large-run resource reservation and authorization absent",
        )
    )
    return {
        "format": FORMAT,
        "relation_id": PRODUCTION_RELATION_ID,
        "candidate_set_identity_sha256": _sha256(
            canonical_json(_candidate_identity_document(candidates))
        ),
        "invocation_identity_sha256": invocation.invocation_sha256,
        "statement_snapshot_sha256": _sha256(invocation.statement_raw),
        "rho_snapshot_sha256": invocation.rho.sha256,
        "same_candidate_snapshots_consumed": True,
        "same_rho_snapshot_consumed": True,
        "candidate_pathnames_reopened": False,
        "rho_pathname_reopened": False,
        "production_input_report": candidate_report,
        "binding_failures": binding_failures,
        "blockers": blockers,
        "safe_to_materialize_production_cache": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "output_created": False,
    }


def execute_production_child(*_args: object, **_kwargs: object) -> None:
    raise ProductionChildExecutorUnavailable(
        "production child executor is unavailable; no output or CAP trace was created"
    )


@dataclass(frozen=True)
class StageOutputIdentityV1:
    relation_id: str
    profile_fingerprint: str
    plan_sha256: str
    invocation_sha256: str
    stage_id: str
    rows: int
    wires: int
    stream_bytes: int
    stream_sha256: str
    outputs: tuple[tuple[str, int, str], ...]
    assignment_materialized: bool
    external_assertions: int
    verification_failures: int

    def document(self) -> dict[str, object]:
        return {
            "format": OUTPUT_IDENTITY_FORMAT,
            "implementation_version": IMPLEMENTATION_VERSION,
            "relation_id": self.relation_id,
            "profile_fingerprint": self.profile_fingerprint,
            "plan_sha256": self.plan_sha256,
            "invocation_sha256": self.invocation_sha256,
            "stage_id": self.stage_id,
            "rows": self.rows,
            "wires": self.wires,
            "stream_bytes": self.stream_bytes,
            "stream_sha256": self.stream_sha256,
            "outputs": [
                {"port_id": port_id, "bit_length": bit_length, "sha256": digest}
                for port_id, bit_length, digest in self.outputs
            ],
            "assignment_materialized": self.assignment_materialized,
            "external_assertions": self.external_assertions,
            "verification_failures": self.verification_failures,
        }

    def encode(self) -> bytes:
        _validate_stage_output_document(self.document())
        return canonical_json(self.document())

    @classmethod
    def decode(cls, raw: bytes) -> "StageOutputIdentityV1":
        try:
            document = launch_io.strict_json(raw)
        except launch_io.ValidationError as error:
            raise ChildExecutorError(str(error)) from error
        _validate_stage_output_document(document)
        outputs = tuple(
            (str(item["port_id"]), int(item["bit_length"]), str(item["sha256"]))
            for item in document["outputs"]
        )
        result = cls(
            relation_id=str(document["relation_id"]),
            profile_fingerprint=str(document["profile_fingerprint"]),
            plan_sha256=str(document["plan_sha256"]),
            invocation_sha256=str(document["invocation_sha256"]),
            stage_id=str(document["stage_id"]),
            rows=int(document["rows"]),
            wires=int(document["wires"]),
            stream_bytes=int(document["stream_bytes"]),
            stream_sha256=str(document["stream_sha256"]),
            outputs=outputs,
            assignment_materialized=bool(document["assignment_materialized"]),
            external_assertions=int(document["external_assertions"]),
            verification_failures=int(document["verification_failures"]),
        )
        if result.encode() != raw:
            raise ChildExecutorError("noncanonical stage output identity")
        return result

    @classmethod
    def decode_for(
        cls,
        raw: bytes,
        *,
        relation_id: str,
        profile_fingerprint: str,
        plan_sha256: str,
        invocation_sha256: str,
        stage_id: str,
    ) -> "StageOutputIdentityV1":
        result = cls.decode(raw)
        expected = (
            relation_id,
            profile_fingerprint,
            plan_sha256,
            invocation_sha256,
            stage_id,
        )
        observed = (
            result.relation_id,
            result.profile_fingerprint,
            result.plan_sha256,
            result.invocation_sha256,
            result.stage_id,
        )
        if observed != expected:
            raise ChildExecutorError("stage output execution-domain binding mismatch")
        return result


def _validate_stage_output_document(document: object) -> None:
    current = _exact_keys(
        document,
        {
            "format",
            "implementation_version",
            "relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "stage_id",
            "rows",
            "wires",
            "stream_bytes",
            "stream_sha256",
            "outputs",
            "assignment_materialized",
            "external_assertions",
            "verification_failures",
        },
        "stage output identity",
    )
    if current["format"] != OUTPUT_IDENTITY_FORMAT:
        raise ChildExecutorError("wrong stage output identity format")
    if current["implementation_version"] != IMPLEMENTATION_VERSION:
        raise ChildExecutorError("wrong stage output identity version")
    for field_name in ("profile_fingerprint", "plan_sha256", "invocation_sha256", "stream_sha256"):
        if not _is_sha256(current[field_name]):
            raise ChildExecutorError(f"invalid {field_name}")
    if type(current["relation_id"]) is not str or not current["relation_id"]:
        raise ChildExecutorError("invalid output relation id")
    if type(current["stage_id"]) is not str or not current["stage_id"]:
        raise ChildExecutorError("invalid output stage id")
    for field_name in ("rows", "wires", "stream_bytes", "external_assertions", "verification_failures"):
        if type(current[field_name]) is not int or current[field_name] < 0:
            raise ChildExecutorError(f"invalid {field_name}")
    if type(current["assignment_materialized"]) is not bool:
        raise ChildExecutorError("invalid assignment materialization flag")
    outputs = current["outputs"]
    if type(outputs) is not list or not outputs:
        raise ChildExecutorError("stage outputs must be a nonempty list")
    seen = set()
    for item in outputs:
        item = _exact_keys(item, {"port_id", "bit_length", "sha256"}, "stage output")
        if type(item["port_id"]) is not str or not item["port_id"] or item["port_id"] in seen:
            raise ChildExecutorError("invalid or duplicate stage output port")
        if type(item["bit_length"]) is not int or item["bit_length"] <= 0:
            raise ChildExecutorError("invalid stage output width")
        if not _is_sha256(item["sha256"]):
            raise ChildExecutorError("invalid stage output digest")
        seen.add(item["port_id"])


def _bounded_cache_identity(invocation: InvocationSnapshotV1) -> dict[str, object]:
    document = {
        "format": "PQRBBC-ISSUANCE-CAP-CHILD-CACHE-IDENTITY-1",
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": BOUNDED_PROFILE,
        "stage_order_sha256": _sha256(canonical_json(list(BOUNDED_STAGE_ORDER))),
        "invocation_sha256": invocation.invocation_sha256,
        "statement_sha256": _sha256(invocation.statement_raw),
        "ticket_message_sha256": _sha256(invocation.ticket_message),
        "blind_mask_sha256": _sha256(invocation.witness.blind_mask),
        "rho_snapshot_sha256": invocation.rho.sha256,
        "predecessor_manifest_sha256": TRACKED_PREREQUISITES[
            "cap576_preflight_manifest"
        ][2],
        "production": False,
    }
    document["cache_identity_sha256"] = _sha256(
        DOMAIN_CACHE + canonical_json(document)
    )
    return document


def _initial_chain(cache_identity: Mapping[str, object]) -> str:
    return _sha256(DOMAIN_CHAIN + canonical_json(cache_identity))


def _stage_record(
    ordinal: int,
    stage_id: str,
    previous_chain_sha256: str,
    result: Mapping[str, object],
) -> dict[str, object]:
    result_sha256 = _sha256(DOMAIN_RESULT + canonical_json(result))
    chain_sha256 = _hash_tuple(
        DOMAIN_CHAIN,
        (
            bytes.fromhex(previous_chain_sha256),
            ordinal.to_bytes(4, "little"),
            stage_id.encode("ascii"),
            bytes.fromhex(result_sha256),
        ),
    )
    return {
        "ordinal": ordinal,
        "stage_id": stage_id,
        "previous_chain_sha256": previous_chain_sha256,
        "result_sha256": result_sha256,
        "chain_sha256": chain_sha256,
    }


def encode_state(
    cache_identity: Mapping[str, object],
    records: Sequence[Mapping[str, object]],
) -> bytes:
    return canonical_json(
        {
            "format": STATE_FORMAT,
            "implementation_version": IMPLEMENTATION_VERSION,
            "relation_id": BOUNDED_RELATION_ID,
            "stage_order": list(BOUNDED_STAGE_ORDER),
            "cache_identity": dict(cache_identity),
            "completed_stage_ids": [record["stage_id"] for record in records],
            "records": [dict(record) for record in records],
        }
    )


def decode_state(
    raw: bytes, expected_cache_identity: Mapping[str, object]
) -> tuple[dict[str, object], ...]:
    try:
        document = launch_io.strict_json(raw)
    except launch_io.ValidationError as error:
        raise ChildExecutorError(str(error)) from error
    document = _exact_keys(
        document,
        {
            "format",
            "implementation_version",
            "relation_id",
            "stage_order",
            "cache_identity",
            "completed_stage_ids",
            "records",
        },
        "executor state",
    )
    if (
        document["format"] != STATE_FORMAT
        or document["implementation_version"] != IMPLEMENTATION_VERSION
        or document["relation_id"] != BOUNDED_RELATION_ID
        or document["stage_order"] != list(BOUNDED_STAGE_ORDER)
        or document["cache_identity"] != dict(expected_cache_identity)
    ):
        raise ChildExecutorError("executor state identity mismatch")
    records = document["records"]
    completed = document["completed_stage_ids"]
    if type(records) is not list or type(completed) is not list:
        raise ChildExecutorError("executor state records are malformed")
    if len(records) > len(BOUNDED_STAGE_ORDER):
        raise ChildExecutorError("executor state exceeds stage plan")
    if completed != list(BOUNDED_STAGE_ORDER[: len(records)]):
        raise ChildExecutorError("executor state is not a contiguous prefix")
    previous = _initial_chain(expected_cache_identity)
    normalized = []
    for ordinal, record in enumerate(records):
        record = _exact_keys(
            record,
            {
                "ordinal",
                "stage_id",
                "previous_chain_sha256",
                "result_sha256",
                "chain_sha256",
            },
            "executor stage record",
        )
        if (
            record["ordinal"] != ordinal
            or record["stage_id"] != BOUNDED_STAGE_ORDER[ordinal]
            or record["previous_chain_sha256"] != previous
            or not _is_sha256(record["result_sha256"])
        ):
            raise ChildExecutorError("executor stage record mismatch")
        expected_chain = _hash_tuple(
            DOMAIN_CHAIN,
            (
                bytes.fromhex(previous),
                ordinal.to_bytes(4, "little"),
                str(record["stage_id"]).encode("ascii"),
                bytes.fromhex(str(record["result_sha256"])),
            ),
        )
        if record["chain_sha256"] != expected_chain:
            raise ChildExecutorError("executor state chain mismatch")
        previous = expected_chain
        normalized.append(dict(record))
    if encode_state(expected_cache_identity, normalized) != raw:
        raise ChildExecutorError("noncanonical executor state")
    return tuple(normalized)


@dataclass(frozen=True)
class BoundedRunResult:
    state_raw: bytes
    evidence: dict[str, object] | None


def _bounded_randomness(invocation: InvocationSnapshotV1) -> cap.CAPRandomness:
    return cap.CAPRandomness(
        invocation.rho.randomness.salt,
        (invocation.rho.randomness.roots[0],),
    )


def _bounded_native_stage(
    invocation: InvocationSnapshotV1,
) -> tuple[dict[str, object], shard.ShardTraceSummary, cap.CAPExecution]:
    randomness = _bounded_randomness(invocation)
    execution = shard.build_parallel_execution(
        BOUNDED_PARAMETERS, randomness, workers=2
    )
    summary = shard.build_streaming_shard(
        BOUNDED_PARAMETERS,
        randomness,
        invocation.ticket_message,
        workers=2,
        execution=execution,
    )
    result = {
        "stage": "native-shard",
        "wrapper_relation_id": BOUNDED_RELATION_ID,
        "engine_reported_relation_id": shard.shard_profile(BOUNDED_PARAMETERS)[1],
        "engine_namespace_production_eligible": False,
        "rows": summary.rows,
        "wires": summary.wires,
        "stream_bytes": summary.stream_bytes,
        "stream_sha256": summary.stream_sha256,
        "spool_bytes": summary.spool_bytes,
        "spool_sha256": summary.spool_sha256,
        "assignment_materialized": summary.assignment_materialized,
        "external_assertions": summary.external_assertions,
        "verification_failures": summary.verification_failures,
    }
    return result, summary, execution


def _bounded_output_identity(
    invocation: InvocationSnapshotV1,
    summary: shard.ShardTraceSummary,
    execution: cap.CAPExecution,
) -> StageOutputIdentityV1:
    commitment = summary.commitment_bytes
    mask = cap.pack_int(
        execution.commitment.derived_mask, BOUNDED_PARAMETERS.mask_bits
    )
    append = cap.pack_int(
        execution.commitment.append_base,
        BOUNDED_PARAMETERS.appended_signature_bits,
    )
    return StageOutputIdentityV1(
        relation_id=BOUNDED_RELATION_ID,
        profile_fingerprint=BOUNDED_PROFILE,
        plan_sha256=_sha256(canonical_json(list(BOUNDED_STAGE_ORDER))),
        invocation_sha256=invocation.invocation_sha256,
        stage_id="bind-child-outputs",
        rows=summary.rows,
        wires=summary.wires,
        stream_bytes=summary.stream_bytes,
        stream_sha256=summary.stream_sha256,
        outputs=(
            ("commitment", len(commitment) * 8, _sha256(commitment)),
            ("derived-mask", BOUNDED_PARAMETERS.mask_bits, _sha256(mask)),
            (
                "append-base",
                BOUNDED_PARAMETERS.appended_signature_bits,
                _sha256(append),
            ),
            (
                "request-hash",
                len(summary.request_hash_bytes) * 8,
                _sha256(summary.request_hash_bytes),
            ),
        ),
        assignment_materialized=summary.assignment_materialized,
        external_assertions=summary.external_assertions,
        verification_failures=summary.verification_failures,
    )


def run_bounded(
    invocation: InvocationSnapshotV1,
    *,
    resume_state_raw: bytes | None = None,
    stop_after: str | None = None,
) -> BoundedRunResult:
    if stop_after is not None and stop_after not in BOUNDED_STAGE_ORDER:
        raise ChildExecutorError("unknown bounded stop stage")
    cache_identity = _bounded_cache_identity(invocation)
    previous_records = (
        ()
        if resume_state_raw is None
        else decode_state(resume_state_raw, cache_identity)
    )
    records: list[dict[str, object]] = []
    results: dict[str, dict[str, object]] = {}
    summary: shard.ShardTraceSummary | None = None
    execution: cap.CAPExecution | None = None
    output_identity: StageOutputIdentityV1 | None = None
    previous_chain = _initial_chain(cache_identity)

    for ordinal, stage_id in enumerate(BOUNDED_STAGE_ORDER):
        if stage_id == "bind-invocation":
            result = {
                "stage": stage_id,
                "invocation_sha256": invocation.invocation_sha256,
                "statement_sha256": _sha256(invocation.statement_raw),
                "ticket_message_sha256": _sha256(invocation.ticket_message),
                "rho_snapshot_sha256": invocation.rho.sha256,
                "same_immutable_rho_raw": True,
                "private_witness_embedded_in_state": False,
            }
        elif stage_id == "native-shard":
            result, summary, execution = _bounded_native_stage(invocation)
        elif stage_id == "bind-child-outputs":
            if summary is None or execution is None:
                raise AssertionError("bounded native stage result missing")
            output_identity = _bounded_output_identity(invocation, summary, execution)
            output_raw = output_identity.encode()
            result = {
                "stage": stage_id,
                "output_identity_bytes": len(output_raw),
                "output_identity_sha256": _sha256(output_raw),
                "output_ports": len(output_identity.outputs),
                "formal_mask_matches_bounded_derived_mask": (
                    invocation.witness.blind_mask
                    == cap.pack_int(
                        execution.commitment.derived_mask,
                        BOUNDED_PARAMETERS.mask_bits,
                    )
                ),
                "full_i3_relation_claimed": False,
            }
        else:
            result = {
                "stage": stage_id,
                "completed_prefix_sha256": previous_chain,
                "bounded_only": True,
                "production_execution_started": False,
                "cryptographic_proofs_generated": 0,
            }
        record = _stage_record(ordinal, stage_id, previous_chain, result)
        if ordinal < len(previous_records) and record != previous_records[ordinal]:
            raise ChildExecutorError(f"resume stage result mismatch: {stage_id}")
        records.append(record)
        results[stage_id] = result
        previous_chain = str(record["chain_sha256"])
        state_raw = encode_state(cache_identity, records)
        if stop_after == stage_id:
            return BoundedRunResult(state_raw, None)

    if output_identity is None or summary is None:
        raise AssertionError("bounded final output identity missing")
    output_raw = output_identity.encode()
    deterministic_result = {
        "relation_id": BOUNDED_RELATION_ID,
        "cache_identity_sha256": cache_identity["cache_identity_sha256"],
        "final_chain_sha256": previous_chain,
        "output_identity_sha256": _sha256(output_raw),
        "state_sha256": _sha256(state_raw),
    }
    evidence = {
        "format": "PQRBBC-ISSUANCE-CAP-CHILD-BOUNDED-RUN-EVIDENCE-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "deterministic_result": deterministic_result,
        "deterministic_result_sha256": _sha256(canonical_json(deterministic_result)),
        "stage_order": list(BOUNDED_STAGE_ORDER),
        "native_observation": results["native-shard"],
        "output_identity": output_identity.document(),
        "resume_state_bytes": len(state_raw),
        "private_statement_or_witness_embedded": False,
        "assignment_or_row_archive_materialized": False,
        "large_relation_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
        "production_execution_started": False,
        "Proof-closed": False,
        "Production-closed": False,
    }
    return BoundedRunResult(state_raw, evidence)


def _fixture_invocation() -> InvocationSnapshotV1:
    current = issuance_relation.fixture()
    return capture_invocation(current.statement, current.witness)


@lru_cache(maxsize=1)
def bounded_executor_self_check() -> dict[str, object]:
    invocation = _fixture_invocation()
    fresh = run_bounded(invocation)
    interrupted = run_bounded(invocation, stop_after="bind-invocation")
    resumed = run_bounded(invocation, resume_state_raw=interrupted.state_raw)
    assert fresh.evidence is not None and resumed.evidence is not None

    state_mutation_rejected = False
    mutated = bytearray(interrupted.state_raw)
    marker = b'"result_sha256":"'
    offset = interrupted.state_raw.find(marker)
    if offset < 0:
        raise AssertionError("bounded state result digest marker missing")
    mutated[offset + len(marker)] = (
        ord("0") if mutated[offset + len(marker)] != ord("0") else ord("1")
    )
    try:
        run_bounded(invocation, resume_state_raw=bytes(mutated))
    except ChildExecutorError:
        state_mutation_rejected = True

    trailing_rejected = False
    try:
        run_bounded(invocation, resume_state_raw=interrupted.state_raw + b"\x00")
    except ChildExecutorError:
        trailing_rejected = True

    wrong_invocation_rejected = False
    changed_statement = replace(
        invocation.statement,
        beta=bytes([invocation.statement.beta[0] ^ 1]) + invocation.statement.beta[1:],
    ).encode()
    changed_invocation = capture_invocation(changed_statement, invocation.witness_raw)
    try:
        run_bounded(changed_invocation, resume_state_raw=interrupted.state_raw)
    except ChildExecutorError:
        wrong_invocation_rejected = True

    production_refused = False
    try:
        execute_production_child(object())
    except ProductionChildExecutorUnavailable:
        production_refused = True

    output_raw = canonical_json(fresh.evidence["output_identity"])
    return {
        "relation_id": BOUNDED_RELATION_ID,
        "test_only": True,
        "production_widths": {
            "mask_bits": BOUNDED_PARAMETERS.mask_bits,
            "appended_signature_bits": BOUNDED_PARAMETERS.appended_signature_bits,
            "witness_bits": BOUNDED_PARAMETERS.witness_bits,
            "random_polynomial_bits": BOUNDED_PARAMETERS.random_polynomial_bits,
        },
        "stage_order": list(BOUNDED_STAGE_ORDER),
        "fresh_state_sha256": _sha256(fresh.state_raw),
        "resumed_state_sha256": _sha256(resumed.state_raw),
        "fresh_result_sha256": fresh.evidence["deterministic_result_sha256"],
        "resumed_result_sha256": resumed.evidence["deterministic_result_sha256"],
        "output_identity_sha256": _sha256(output_raw),
        "native_observation": fresh.evidence["native_observation"],
        "fresh_and_resume_identical": fresh.state_raw == resumed.state_raw,
        "state_mutation_rejected": state_mutation_rejected,
        "trailing_bytes_rejected": trailing_rejected,
        "wrong_invocation_rejected": wrong_invocation_rejected,
        "production_refused_before_output_or_trace": production_refused,
        # The formal fixture mask is not a witness for this four-leaf child-only run.
        "formal_mask_matches_bounded_derived_mask": False,
        "full_i3_relation_claimed": False,
        "large_relation_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
        "assignment_or_row_archive_materialized": False,
        "frozen_mismatches": [
            label
            for label, observed, frozen in (
                ("production_plan", production_plan_sha256(), FROZEN_PRODUCTION_PLAN_SHA256),
                ("bounded_state", _sha256(fresh.state_raw), FROZEN_BOUNDED_STATE_SHA256),
                (
                    "bounded_result",
                    str(fresh.evidence["deterministic_result_sha256"]),
                    FROZEN_BOUNDED_RESULT_SHA256,
                ),
                ("output_identity", _sha256(output_raw), FROZEN_BOUNDED_OUTPUT_IDENTITY_SHA256),
            )
            if frozen and observed != frozen
        ],
    }


def build_manifest() -> dict[str, object]:
    bounded = bounded_executor_self_check()
    plan = build_production_execution_plan()
    tracked_failures = list(validate_tracked_prerequisites())
    plan_failures = list(validate_production_plan())
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": PRODUCTION_RELATION_ID,
        "production_plan": {
            "sha256": production_plan_sha256(),
            "stage_count": len(PRODUCTION_STAGE_ORDER),
            "stage_order": list(PRODUCTION_STAGE_ORDER),
            "tree_count": len(plan["tree_contracts"]),
            "tree_contracts": plan["tree_contracts"],
            "split_dependency_order_frozen": True,
            "legacy_monolithic_runner_directly_usable": False,
            "production_execution_started": False,
        },
        "invocation_contract": {
            "statement_and_witness_canonical": True,
            "ticket_message_derivation": "SHAKE256(PQ-RBBC/TICKET || exact TicketPayload)[0:32]",
            "rho_bytes": predecessor.PRODUCTION_RHO_BYTES,
            "rho_profile_fingerprint": predecessor.PRODUCTION_PROFILE,
            "same_candidate_set_snapshots_required": True,
            "same_rho_snapshot_required": True,
            "candidate_pathnames_may_be_reopened": False,
            "rho_pathname_may_be_reopened": False,
            "private_witness_may_be_embedded_in_state_or_evidence": False,
        },
        "cache_resume_contract": {
            "format": STATE_FORMAT,
            "cache_identity_fields": sorted(_bounded_cache_identity(_fixture_invocation())),
            "canonical_json_only": True,
            "pickle_permitted": False,
            "completed_stages_are_contiguous_prefix": True,
            "stage_result_chain_domain_hex": DOMAIN_CHAIN.hex(),
            "fresh_cache_must_not_exist": True,
            "resume_requires_exact_external_state_sha256": True,
            "state_is_external_runtime_artifact": True,
            "state_tracked_in_git": False,
            "production_publisher_implemented": False,
            "production_resume_durability_qualified": False,
        },
        "per_stage_output_identity_contract": {
            "format": OUTPUT_IDENTITY_FORMAT,
            "implemented_and_tested_on_bounded_shard": True,
            "binds_relation_profile_plan_invocation_stage": True,
            "binds_rows_wires_stream_identity_and_output_digests": True,
            "fresh_production_output_digests_currently": None,
            "historical_output_values_accepted_as_fresh": False,
            "production_identity_instantiated": False,
        },
        "bounded_executor": bounded,
        "external_artifacts": {
            "required": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "installed_in_checkpoint_environment": [],
            "missing": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "independent_review_required": True,
            "resource_reservation_required": True,
            "large_run_authorization_required": True,
        },
        "resource_estimate": {
            "bounded_cpu_cores": 2,
            "bounded_elapsed_seconds_upper_bound": 90,
            "bounded_peak_memory_mib_upper_bound": 128,
            "historical_18_tree_combined_rows": 589_030_555,
            "fresh_18_tree_estimated_seconds": [8_000, 12_000],
            "fresh_18_tree_minimum_memory_bytes": 16_000_000_000,
            "fresh_18_tree_minimum_free_disk_bytes": 64_000_000_000,
            "fresh_estimate_requires_new_reservation": True,
            "other_tree_observed_stream_bytes_used": False,
        },
        "exact_commands": {
            "bounded_executor_self_check": (
                "PYTHONPATH=src python -u src/"
                "pq_rbbc_issuance_cap_child_executor_v1.py --self-check"
            ),
            "read_only_external_preflight": (
                "PYTHONPATH=src python -u src/"
                "pq_rbbc_issuance_cap_child_executor_v1.py --artifact-root "
                "/ABSOLUTE/PRIVATE/ARTIFACT/ROOT"
            ),
            "targeted_tests": (
                "PYTHONPATH=src python -m unittest "
                "tests.test_pq_rbbc_issuance_cap_child_executor_v1 -v"
            ),
            "production_execution": None,
            "large_replay": None,
            "large_proving": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": {"bounded_test_only": True, "production": False},
            "Implemented": {"bounded_staged_executor": True, "production": False},
            "Tested": {"bounded_fresh_resume_mutation": True, "production": False},
            "Evidence-sealed": {"bounded_metadata": True, "production": False},
            "Proof-closed": False,
            "Production-closed": False,
            "fresh_production_namespace_defined": not plan_failures,
            "production_stage_contract_frozen": not plan_failures,
            "production_per_tree_outputs_materialized": False,
            "production_runner_qualified": False,
            "production_relation_instantiated": False,
            "formal_pi_issue_generated": False,
            "qualified_pq_se_backend_integrated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "artifact_policy": {
            "assignment_or_br1cs_created": False,
            "row_archive_created": False,
            "pickle_created": False,
            "cache_checkpoint_resume_or_log_tracked": False,
            "large_proving_output_created": False,
            "historical_files_modified": False,
            "historical_assignment_or_values_reused": False,
            "other_tree_observed_stream_bytes_used": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "tracked_prerequisites": {
            name: {"path": path, "bytes": size, "sha256": digest}
            for name, (path, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": tracked_failures,
        "production_plan_validation_failures": plan_failures,
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_cap_child_executor_manifest_v1.json"
    manifest_identity = (
        _identity(manifest_path)
        if manifest_path.is_file()
        else {
            "filename": manifest_path.name,
            "bytes": len(canonical_json(build_manifest())),
            "sha256": _sha256(canonical_json(build_manifest())),
        }
    )
    bounded = bounded_executor_self_check()
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": PRODUCTION_RELATION_ID,
        "manifest": manifest_identity,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "production_plan_valid": not validate_production_plan(),
        "production_plan_sha256": production_plan_sha256(),
        "production_stage_count": len(PRODUCTION_STAGE_ORDER),
        "production_tree_count": 18,
        "bounded_executor": bounded,
        "external_artifacts_present": 0,
        "external_artifacts_required": len(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        "missing_external_artifacts": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        "private_statement_witness_or_rho_embedded": False,
        "production_output_identity_instantiated": False,
        "production_execution_started": False,
        "large_replay_started": False,
        "large_proving_started": False,
        "formal_pi_issue_generated": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "Proof-closed": False,
        "Production-closed": False,
        "historical_assignment_or_values_reused": False,
        "other_tree_observed_stream_bytes_used": False,
        "large_artifacts_embedded": False,
        "portable_evidence_contains_absolute_paths": False,
    }


def external_inventory_preflight(artifact_root: Path) -> dict[str, object]:
    report = predecessor.read_only_preflight(artifact_root)
    return {
        "format": FORMAT,
        "relation_id": PRODUCTION_RELATION_ID,
        "predecessor_report": report,
        "fresh_production_plan_valid": not validate_production_plan(),
        "production_invocation_present": False,
        "production_output_created": False,
        "safe_to_materialize_production_cache": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--artifact-root", type=Path)
    mode.add_argument("--print-manifest", action="store_true")
    mode.add_argument("--print-evidence", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        document = bounded_executor_self_check()
    elif args.artifact_root is not None:
        document = external_inventory_preflight(args.artifact_root)
    elif args.print_manifest:
        document = build_manifest()
    else:
        document = build_portable_evidence()
    print(canonical_json(document).decode("ascii"), end="")


if __name__ == "__main__":
    main()
