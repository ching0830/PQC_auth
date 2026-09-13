from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_production_inputs_v1 as inputs
import pq_rbbc_launch_io_v2_41 as launch_io
from pq_rbbc.contracts.system import (
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.system_init import AuthenticatedSystemInitialization


ROOT = Path(__file__).resolve().parents[1]


def fixed(label: bytes) -> bytes:
    return hashlib.sha256(b"PQ-RBBC/production-inputs-test/" + label).digest()


def identity(filename: str, raw: bytes) -> dict[str, object]:
    return {
        "filename": filename,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def snapshot(filename: str, raw: bytes) -> launch_io.Snapshot:
    return launch_io.Snapshot(Path("/test-only") / filename, raw)


def reference_keys() -> tuple[KeyReference, ...]:
    return tuple(
        KeyReference(
            role=role,
            key_id=fixed(b"key-id/" + role.name.encode("ascii")),
            public_key_digest=fixed(b"public-key/" + role.name.encode("ascii")),
        )
        for role in KeyRole
    )


def complete_structural_candidate() -> inputs.CandidateSet:
    # Deliberately synthetic bytes.  They can satisfy structural validation but
    # cannot pass the checkpoint's external trust/authenticity blockers.
    trace_raw = inputs.TracePublicKeyV1(bytes(inputs.TRACE_KEY_BODY_BYTES)).encode()
    trace_id = identity(inputs.TRACE_KEY_FILENAME, trace_raw)
    certification = {
        "format": "PQRBBC-TRACE-PUBLIC-KEY-CERTIFICATION-1",
        "gate_id": inputs.GATE_ID,
        "trace_key_identity": trace_id,
        "trace_profile_digest": inputs.TRACE_PROFILE_DIGEST.hex(),
        "parameter_set": {
            "encoding_id": inputs.TRACE_KEY_ENCODING_ID,
            "k": inputs.reference.K,
            "n": inputs.reference.N,
            "scheme_id": inputs.TRACE_SCHEME_ID,
            "t": inputs.reference.T,
        },
        "generation": {
            "implementation_id": "TEST-ONLY-GOPPA-GENERATOR-STUB",
            "implementation_version": "0",
            "source_identity": identity("test-generator.txt", b"test-only"),
            "test_fixture": False,
        },
        "ceremony_transcript_identity": identity("ceremony.json", b"test-only"),
        "producer_attestation_identity": identity("producer.sig", b"test-only"),
        "claim_boundary": {
            "goppa_construction_attested": True,
            "production_use_authorized": True,
            "structural_encoding_validated": True,
        },
    }
    certification_raw = inputs.canonical_json(certification)

    keys = reference_keys()
    issuer_key = next(key for key in keys if key.role is KeyRole.ISSUER_VERIFICATION)
    common = inputs.ProductionIssuanceCommonParametersV1(
        trace_public_key_sha256=hashlib.sha256(trace_raw).digest(),
        trace_certification_sha256=hashlib.sha256(certification_raw).digest(),
        issuer_verification_key_digest=issuer_key.public_key_digest,
    ).encode()
    opening_key = next(key for key in keys if key.role is KeyRole.OPENING_ENCRYPTION)
    configuration = SystemConfiguration(
        protocol_version=1,
        epoch=7,
        domain=fixed(b"domain"),
        policy_digest=fixed(b"policy"),
        expiry_bucket=2_000_000_000,
        oa_key_id=opening_key.key_id,
        issuer_key_id=issuer_key.key_id,
    )
    bundle = SystemInitializationBundle(
        configuration=configuration,
        common_parameters_digest=hashlib.sha256(common).digest(),
        federation_policy=ThresholdPolicy(5, 3),
        opening_policy=ThresholdPolicy(7, 5),
        keys=keys,
    )
    initialization = AuthenticatedSystemInitialization(
        bundle=bundle,
        authentication=b"TEST-ONLY-NOT-A-SIGNATURE",
    ).encode()

    reviewed = {
        "trace_key": trace_id,
        "trace_certification": identity(
            inputs.TRACE_CERTIFICATION_FILENAME, certification_raw
        ),
        "initialization": identity(inputs.INITIALIZATION_FILENAME, initialization),
        "common_parameters": identity(inputs.COMMON_PARAMETERS_FILENAME, common),
    }
    review = {
        "format": "PQRBBC-ISSUANCE-PRODUCTION-INPUTS-REVIEW-1",
        "gate_id": inputs.GATE_ID,
        "reviewed_identities": reviewed,
        "scope": [
            "canonical_common_parameters",
            "certified_trace_public_key",
            "authenticated_system_initialization",
            "CAP.Commit-to-H_RBBC-adapter",
        ],
        "disposition": "accept",
        "reviewer": {
            "reviewer_id": "TEST-ONLY-REVIEWER",
            "organization": "TEST-ONLY-ORGANIZATION",
        },
        "attestation_identity": identity("review.sig", b"test-only"),
        "claim_boundary": {
            "cryptographic_proof_closed": False,
            "independent_review_completed": True,
            "production_inputs_accepted": True,
            "production_relation_closed": False,
        },
    }
    review_raw = inputs.canonical_json(review)
    return inputs.CandidateSet(
        root=Path("/test-only"),
        trace_key=snapshot(inputs.TRACE_KEY_FILENAME, trace_raw),
        trace_certification=snapshot(
            inputs.TRACE_CERTIFICATION_FILENAME, certification_raw
        ),
        initialization=snapshot(inputs.INITIALIZATION_FILENAME, initialization),
        common_parameters=snapshot(inputs.COMMON_PARAMETERS_FILENAME, common),
        independent_review=snapshot(inputs.INDEPENDENT_REVIEW_FILENAME, review_raw),
    )


class TracePublicKeyCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key = inputs.TracePublicKeyV1(bytes(inputs.TRACE_KEY_BODY_BYTES))
        cls.encoded = cls.key.encode()

    def test_round_trip_and_exact_shape(self) -> None:
        self.assertEqual(inputs.TracePublicKeyV1.decode(self.encoded), self.key)
        self.assertEqual(
            len(self.encoded),
            inputs.build_manifest()["trace_public_key_contract"]["encoded_bytes"],
        )
        self.assertLessEqual(len(self.encoded), launch_io.MAX_JSON_BYTES)

    def test_wrong_version_section_order_length_and_trailing_reject(self) -> None:
        wrong_version = bytearray(self.encoded)
        wrong_version[len(inputs.TRACE_KEY_MAGIC)] ^= 1
        wrong_section = bytearray(self.encoded)
        wrong_section[len(inputs.TRACE_KEY_MAGIC) + 4] ^= 1
        cases = (
            bytes(wrong_version),
            bytes(wrong_section),
            self.encoded[:-1],
            self.encoded + b"\x00",
        )
        for candidate in cases:
            with self.subTest(length=len(candidate)):
                with self.assertRaises(inputs.ProductionInputsError):
                    inputs.TracePublicKeyV1.decode(candidate)

    def test_structural_parse_is_not_goppa_certification(self) -> None:
        manifest = inputs.build_manifest()
        self.assertFalse(
            manifest["trace_public_key_contract"][
                "shape_validation_is_goppa_certification"
            ]
        )
        self.assertFalse(manifest["claim_boundary"]["Production-closed"])


class CommonParametersCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = inputs.ProductionIssuanceCommonParametersV1(
            fixed(b"trace-key"),
            fixed(b"trace-certification"),
            fixed(b"issuer-key"),
        )
        self.encoded = self.value.encode()

    def test_round_trip_and_protocol_profiles(self) -> None:
        self.assertEqual(
            inputs.ProductionIssuanceCommonParametersV1.decode(self.encoded),
            self.value,
        )
        manifest = inputs.build_manifest()["common_parameters_contract"]
        self.assertEqual(manifest["cap_profile_fingerprint"], inputs.CAP_PROFILE_FINGERPRINT)
        self.assertEqual(
            manifest["h_rbbc_profile_fingerprint"],
            inputs.H_RBBC_PROFILE_FINGERPRINT,
        )

    def test_wrong_version_order_truncation_and_trailing_reject(self) -> None:
        wrong_version = bytearray(self.encoded)
        wrong_version[len(inputs.COMMON_PARAMETERS_MAGIC)] ^= 1
        wrong_section = bytearray(self.encoded)
        wrong_section[len(inputs.COMMON_PARAMETERS_MAGIC) + 4] ^= 1
        for candidate in (
            bytes(wrong_version),
            bytes(wrong_section),
            self.encoded[:-1],
            self.encoded + b"\x00",
        ):
            with self.assertRaises(inputs.ProductionInputsError):
                inputs.ProductionIssuanceCommonParametersV1.decode(candidate)


class CAPToHRBBCAdapterTests(unittest.TestCase):
    def test_general_randomness_decoder_round_trip_and_mutations(self) -> None:
        parameters = inputs.INSECURE_TEST_ONLY_ADAPTER_PARAMETERS
        randomness = cap.deterministic_randomness(parameters, b"decoder-test")
        encoded = randomness.serialize(parameters)
        self.assertEqual(inputs.decode_cap_randomness(parameters, encoded), randomness)
        with self.assertRaises(inputs.ProductionInputsError):
            inputs.decode_cap_randomness(parameters, encoded + b"\x00")
        with self.assertRaises(inputs.ProductionInputsError):
            inputs.decode_cap_randomness(cap.PRODUCTION_PARAMETERS, encoded)
        noncanonical = bytearray(encoded)
        first_field_last_byte = len(cap.RANDOMNESS_MAGIC) + 64 + 24
        noncanonical[first_field_last_byte] |= 0x80
        with self.assertRaises(inputs.ProductionInputsError):
            inputs.decode_cap_randomness(parameters, bytes(noncanonical))

    def test_bounded_real_adapter_supports_distinct_rho(self) -> None:
        result = inputs.bounded_adapter_self_check()
        self.assertTrue(result["same_cap_and_h_rbbc_code_paths"])
        self.assertTrue(result["distinct_rho_supported"])
        self.assertFalse(result["secure_profile"])
        self.assertEqual(result["relation_constraints_replayed"], 0)

    def test_production_refuses_before_cap_execution(self) -> None:
        adapter = inputs.CAPToHRBBCAdapterV1(cap.PRODUCTION_PARAMETERS)
        with patch.object(cap, "execute_cap_commit") as execute:
            with self.assertRaises(inputs.ProductionInputsUnavailable):
                adapter.derive_request(
                    bytes(32),
                    bytes(72),
                    b"not-read-before-production-refusal",
                )
            execute.assert_not_called()
        with self.assertRaises(TypeError):
            inputs.CAPToHRBBCAdapterV1(  # type: ignore[call-arg]
                cap.PRODUCTION_PARAMETERS,
                production_inputs_qualified=True,
            )

    def test_wrong_formal_mask_rejects(self) -> None:
        parameters = inputs.INSECURE_TEST_ONLY_ADAPTER_PARAMETERS
        randomness = cap.deterministic_randomness(parameters, b"wrong-mask-test")
        encoded = randomness.serialize(parameters)
        execution = cap.execute_cap_commit(parameters, randomness)
        mask = bytearray(
            execution.commitment.derived_mask.to_bytes(72, "little")
        )
        mask[0] ^= 1
        with self.assertRaises(inputs.ProductionInputsError):
            inputs.CAPToHRBBCAdapterV1(parameters).derive_request(
                bytes(32), bytes(mask), encoded
            )


class ProductionInputPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.candidates = complete_structural_candidate()

    def test_complete_structural_candidate_remains_production_blocked(self) -> None:
        report = inputs.evaluate_candidate_set(self.candidates)
        self.assertTrue(report["structural_candidate_complete"], report)
        self.assertFalse(report["trusted_handoff_complete"])
        self.assertFalse(report["safe_to_instantiate_production_relation"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])

    def test_missing_inventory_reports_all_five_inputs(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            candidates = inputs.read_candidate_set(Path(directory))
        report = inputs.evaluate_candidate_set(candidates)
        self.assertEqual(
            report["missing_artifacts"], list(inputs.REQUIRED_EXTERNAL_ARTIFACTS)
        )
        self.assertFalse(report["structural_candidate_complete"])

    def test_trace_key_mutation_cannot_be_replaced_by_pathname(self) -> None:
        original = self.candidates.trace_key
        assert original is not None
        changed = launch_io.Snapshot(original.location, original.raw[:-1] + b"\x01")
        report = inputs.evaluate_candidate_set(
            replace(self.candidates, trace_key=changed)
        )
        self.assertFalse(report["structural_candidate_complete"])
        self.assertTrue(report["validation_failures"])
        self.assertEqual(original.identity, snapshot(original.location.name, original.raw).identity)

    def test_review_wrong_identity_and_trailing_bytes_reject(self) -> None:
        review = self.candidates.independent_review
        assert review is not None
        trailing = launch_io.Snapshot(review.location, review.raw + b" ")
        report = inputs.evaluate_candidate_set(
            replace(self.candidates, independent_review=trailing)
        )
        self.assertFalse(report["structural_candidate_complete"])

    def test_common_parameters_wrong_issuer_key_rejects(self) -> None:
        common_snapshot = self.candidates.common_parameters
        assert common_snapshot is not None
        common = inputs.ProductionIssuanceCommonParametersV1.decode(
            common_snapshot.raw
        )
        changed = replace(
            common, issuer_verification_key_digest=fixed(b"wrong-issuer-key")
        ).encode()
        report = inputs.evaluate_candidate_set(
            replace(
                self.candidates,
                common_parameters=launch_io.Snapshot(common_snapshot.location, changed),
            )
        )
        self.assertFalse(report["structural_candidate_complete"])

    def test_snapshot_location_mismatch_rejects(self) -> None:
        trace = self.candidates.trace_key
        assert trace is not None
        wrong_location = launch_io.Snapshot(Path("/elsewhere/key.bin"), trace.raw)
        report = inputs.evaluate_candidate_set(
            replace(self.candidates, trace_key=wrong_location)
        )
        self.assertFalse(report["structural_candidate_complete"])
        self.assertIn(
            f"{inputs.TRACE_KEY_FILENAME}:snapshot location mismatch",
            report["validation_failures"],
        )

    def test_candidate_snapshots_are_the_only_validation_source(self) -> None:
        report_a = inputs.evaluate_candidate_set(self.candidates)
        report_b = inputs.evaluate_candidate_set(self.candidates)
        self.assertEqual(report_a, report_b)
        manifest = inputs.build_manifest()["snapshot_contract"]
        self.assertTrue(manifest["future_executor_must_consume_candidate_set_snapshots"])
        self.assertFalse(manifest["future_executor_may_reopen_pathnames"])


class FrozenCheckpointTests(unittest.TestCase):
    def test_tracked_prerequisites_are_exact(self) -> None:
        self.assertEqual(inputs.validate_tracked_prerequisites(), ())

    def test_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_issuance_production_inputs_manifest_v1.json"
        self.assertEqual(path.read_bytes(), inputs.canonical_json(inputs.build_manifest()))

    def test_portable_evidence_matches_generator(self) -> None:
        path = (
            ROOT
            / "artifacts/metadata/issuance_production_inputs_v1/"
            "pq_rbbc_issuance_production_inputs_portable_evidence_v1.json"
        )
        self.assertEqual(
            path.read_bytes(),
            inputs.canonical_json(inputs.build_portable_evidence()),
        )
        evidence = path.read_bytes()
        self.assertNotIn(b"witness_hex", evidence)
        self.assertNotIn(b"ticket_payload", evidence)


if __name__ == "__main__":
    unittest.main()
