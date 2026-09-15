from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.application import (
    FIRST_APPLICATION_SEQUENCE,
    DeliveryClaimDispositionV2,
    DeliveryClaimResultV2,
    FGSFirstApplicationRecordProcessorV2,
    FGSFirstRecordDispositionV2,
    FirstApplicationRecordV2,
    FirstRecordOutboxStateV2,
    InMemoryFirstApplicationDeliveryStoreV2,
    UEFirstApplicationRecordProcessorV2,
    UEFirstRecordDispositionV2,
    decode_first_application_record,
    derive_first_application_aad,
    derive_first_application_nonce_context,
    encode_first_application_record,
    first_application_checkpoint_manifest,
)
from pq_sat_auth.v2.activation import FGSActivationProcessorV2
from pq_sat_auth.v2.dispatch import application_dispatch_manifest
from pq_sat_auth.v2.framing import FRAME_HEADER_BYTES
from pq_sat_auth.v2.replay import GrantStateV2
from pq_sat_auth.v2.storage.sqlite_first_record import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    FirstRecordOutboxIntegrityError,
    SQLiteFirstRecordOutboxV2,
    sqlite_first_record_outbox_manifest,
)
from pq_sat_auth.v2.storage.sqlite_delivery import (
    sqlite_first_application_delivery_manifest,
)
from pq_sat_auth.v2.storage.sqlite_inbox import (
    sqlite_first_application_inbox_manifest,
)
from pq_sat_auth.v2.storage.sqlite_authoritative import (
    sqlite_authoritative_activation_inbox_manifest,
)
from pq_sat_auth.v2.storage.sqlite_scoped_revocation import (
    sqlite_scoped_revocation_manifest,
)
from pq_sat_auth.v2.storage.sqlite_unified import (
    sqlite_unified_activation_inbox_manifest,
)
from tests.system.test_pq_sat_auth_activation_v2 import (
    ActivationKeySchedule,
    ActivationRevocationProvider,
)
from tests.system.test_pq_sat_auth_grant_v2 import GrantClock
from tests.system.test_pq_sat_auth_processor_v2 import NOW, fixed
from tests.system.test_pq_sat_auth_ue_v2 import UEAccessAcceptFixture


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_first_application_v0_2.json"
PLAINTEXT = b"GET /satellite/status HTTP/1.1\r\n\r\n"


class ApplicationProtectionTestBackend:
    suite_id = 0xFFFF
    production_ready = False

    def __init__(self) -> None:
        self.seal_calls = 0
        self.open_calls = 0
        self.broken_seal = False
        self.broken_open = False
        self.invalid_seal = False
        self.invalid_open = False

    @staticmethod
    def _stream(key: bytes, nonce_context: bytes, aad: bytes, length: int) -> bytes:
        return hashlib.shake_256(
            b"TEST-ONLY/FIRST-APPLICATION/STREAM"
            + key
            + nonce_context
            + aad
        ).digest(length)

    def seal(
        self,
        key: bytes,
        *,
        nonce_context: bytes,
        aad: bytes,
        plaintext: bytes,
    ) -> bytes:
        self.seal_calls += 1
        if self.broken_seal:
            raise RuntimeError("test application seal failed")
        if self.invalid_seal:
            return b""  # type: ignore[return-value]
        stream = self._stream(key, nonce_context, aad, len(plaintext))
        body = bytes(left ^ right for left, right in zip(plaintext, stream))
        tag = hmac.new(
            key,
            nonce_context + aad + body,
            hashlib.sha256,
        ).digest()
        return tag + body

    def open(
        self,
        key: bytes,
        *,
        nonce_context: bytes,
        aad: bytes,
        ciphertext: bytes,
    ) -> bytes:
        self.open_calls += 1
        if self.broken_open:
            raise RuntimeError("test application open failed")
        if self.invalid_open:
            return b""  # type: ignore[return-value]
        if len(ciphertext) <= hashlib.sha256().digest_size:
            raise ValueError("test application ciphertext is truncated")
        tag = ciphertext[: hashlib.sha256().digest_size]
        body = ciphertext[hashlib.sha256().digest_size :]
        expected = hmac.new(
            key,
            nonce_context + aad + body,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("test application authentication failed")
        stream = self._stream(key, nonce_context, aad, len(body))
        return bytes(left ^ right for left, right in zip(body, stream))


class RaiseAfterFinalizeOutbox:
    durable_reference = True
    distributed = False
    production_ready = False

    def __init__(self, delegate: SQLiteFirstRecordOutboxV2) -> None:
        self.delegate = delegate

    def load(self, session_id):
        return self.delegate.load(session_id)

    def reserve(self, candidate):
        return self.delegate.reserve(candidate)

    def finalize(self, candidate, record_bytes):
        self.delegate.finalize(candidate, record_bytes)
        raise OSError("simulated lost outbox commit acknowledgement")


class BrokenDeliveryStore:
    durable = False
    distributed = False
    production_ready = False

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def claim(self, session_id, record_digest):
        if self.mode == "raise":
            raise OSError("delivery store unavailable")
        if self.mode == "wrong_type":
            return object()
        if self.mode == "mutate":
            return DeliveryClaimResultV2(
                DeliveryClaimDispositionV2.NEW,
                session_id,
                fixed(b"wrong-delivery-record"),
            )
        raise AssertionError("unknown test mode")


def _outbox_prepare_worker(path: str, session, plaintext: bytes, start, output):
    try:
        processor = UEFirstApplicationRecordProcessorV2(
            outbox=SQLiteFirstRecordOutboxV2(
                Path(path),
                busy_timeout_ms=20_000,
            ),
            clock=GrantClock(),
            protection_backend=ApplicationProtectionTestBackend(),
        )
        start.wait(10)
        result = processor.process(session, plaintext)
        output.put(
            (
                "ok",
                result.accepted,
                result.disposition.value,
                result.record_bytes,
                result.failures,
            )
        )
    except Exception as error:
        output.put(("error", f"{type(error).__name__}:{error}"))


class FirstApplicationFixture(UEAccessAcceptFixture):
    def setUp(self) -> None:
        super().setUp()
        accepted = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assertTrue(accepted.accepted, accepted.failures)
        assert accepted.session is not None
        self.session = accepted.session
        self.temporary = tempfile.TemporaryDirectory()
        self.outbox_path = Path(self.temporary.name) / "first-record.sqlite3"
        self.outbox = SQLiteFirstRecordOutboxV2(self.outbox_path)
        self.application_protection = ApplicationProtectionTestBackend()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ue_first_processor(self, **overrides: object):
        arguments = {
            "outbox": self.outbox,
            "clock": self.ue_clock,
            "protection_backend": self.application_protection,
        }
        arguments.update(overrides)
        return UEFirstApplicationRecordProcessorV2(**arguments)  # type: ignore[arg-type]

    def activation_processor(self):
        return FGSActivationProcessorV2(
            replay_store=self.store,
            clock=GrantClock(),
            revocation_provider=ActivationRevocationProvider(
                self.grant_record.revocation_generation
            ),
            key_schedule_backend=ActivationKeySchedule(),
            recovery_backend=self.recovery,
        )

    def fgs_first_processor(self, **overrides: object):
        arguments = {
            "activation_processor": self.activation_processor(),
            "protection_backend": self.application_protection,
            "delivery_store": InMemoryFirstApplicationDeliveryStoreV2(),
        }
        arguments.update(overrides)
        return FGSFirstApplicationRecordProcessorV2(**arguments)  # type: ignore[arg-type]

    def prepare(self, plaintext: bytes = PLAINTEXT):
        result = self.ue_first_processor().process(self.session, plaintext)
        self.assertTrue(result.accepted, result.failures)
        assert result.record is not None
        assert result.record_bytes is not None
        return result


class FirstApplicationCodecTests(FirstApplicationFixture):
    def test_manifest_matches_implementation(self) -> None:
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            expected,
            {
                "checkpoint": first_application_checkpoint_manifest(),
                "dispatch": application_dispatch_manifest(),
                "sqlite_delivery": sqlite_first_application_delivery_manifest(),
                "sqlite_inbox": sqlite_first_application_inbox_manifest(),
                "sqlite_outbox": sqlite_first_record_outbox_manifest(),
                "sqlite_authoritative": (
                    sqlite_authoritative_activation_inbox_manifest()
                ),
                "sqlite_scoped_revocation": (
                    sqlite_scoped_revocation_manifest()
                ),
                "sqlite_unified": sqlite_unified_activation_inbox_manifest(),
            },
        )

    def test_record_round_trip_and_frozen_vector(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        assert prepared.record_bytes is not None
        self.assertEqual(
            decode_first_application_record(prepared.record_bytes),
            prepared.record,
        )
        self.assertEqual(
            encode_first_application_record(prepared.record),
            prepared.record_bytes,
        )
        self.assertEqual(prepared.record.sequence_number, 0)
        self.assertEqual(
            hashlib.sha256(prepared.record_bytes).hexdigest(),
            "01cec1683e29795a42db4589a7b412a2137ae0ea589e2a3a96f917cbcf73d0a8",
        )

    def test_decoder_rejects_wrong_type_truncation_trailing_and_sequence(self) -> None:
        prepared = self.prepare()
        assert prepared.record_bytes is not None
        mutations = (
            self.session.activation_bytes,
            prepared.record_bytes[:-1],
            prepared.record_bytes + b"\x00",
            prepared.record_bytes[: FRAME_HEADER_BYTES + 130]
            + (1).to_bytes(8, "big")
            + prepared.record_bytes[FRAME_HEADER_BYTES + 138 :],
        )
        for mutated in mutations:
            with self.subTest(length=len(mutated)):
                with self.assertRaises((TypeError, ValueError)):
                    decode_first_application_record(mutated)

    def test_aad_and_nonce_bind_exact_flow_and_sequence_zero(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        record = prepared.record
        aad = derive_first_application_aad(record)
        self.assertIn(record.activation_bytes, aad)
        self.assertNotIn(record.ciphertext, aad)
        nonce = derive_first_application_nonce_context(
            record.suite_id,
            record.session_id,
        )
        self.assertEqual(len(nonce), 32)
        self.assertNotEqual(
            nonce,
            derive_first_application_nonce_context(
                record.suite_id,
                fixed(b"other-session"),
            ),
        )
        with self.assertRaisesRegex(ValueError, "sequence must be zero"):
            derive_first_application_nonce_context(
                record.suite_id,
                record.session_id,
                1,
            )


class UEFirstApplicationOutboxTests(FirstApplicationFixture):
    def test_exact_record_is_committed_and_read_back_before_release(self) -> None:
        result = self.ue_first_processor().process(self.session, PLAINTEXT)
        self.assertTrue(result.accepted, result.failures)
        self.assertIs(result.disposition, UEFirstRecordDispositionV2.PREPARED_NEW)
        self.assertIsNotNone(result.record_bytes)
        stored = self.outbox.load(self.session.session_id)
        self.assertEqual(stored, result.entry)
        assert stored is not None
        self.assertIs(stored.state, FirstRecordOutboxStateV2.READY)

    def test_restart_retry_returns_exact_record_without_resealing(self) -> None:
        first = self.prepare()
        calls = self.application_protection.seal_calls
        restarted = SQLiteFirstRecordOutboxV2(self.outbox_path)
        retry = self.ue_first_processor(outbox=restarted).process(
            self.session,
            PLAINTEXT,
        )
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            UEFirstRecordDispositionV2.PREPARED_RECOVERED,
        )
        self.assertEqual(retry.record_bytes, first.record_bytes)
        self.assertEqual(self.application_protection.seal_calls, calls)

    def test_competing_plaintext_is_rejected_without_nonce_reuse(self) -> None:
        self.prepare()
        calls = self.application_protection.seal_calls
        conflict = self.ue_first_processor().process(
            self.session,
            b"POST /competing HTTP/1.1\r\n\r\n",
        )
        self.assertFalse(conflict.accepted)
        self.assertIs(conflict.disposition, UEFirstRecordDispositionV2.REJECTED)
        self.assertEqual(conflict.failures, ("outbox_conflict",))
        self.assertEqual(self.application_protection.seal_calls, calls)

    def test_lost_finalize_ack_releases_nothing_then_retry_recovers(self) -> None:
        uncertain = self.ue_first_processor(
            outbox=RaiseAfterFinalizeOutbox(self.outbox)
        ).process(self.session, PLAINTEXT)
        self.assertFalse(uncertain.accepted)
        self.assertIs(
            uncertain.disposition,
            UEFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIsNone(uncertain.record_bytes)
        retry = self.ue_first_processor().process(self.session, PLAINTEXT)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            UEFirstRecordDispositionV2.PREPARED_RECOVERED,
        )

    def test_parallel_exact_prepare_has_one_finalize_winner(self) -> None:
        workers = 12
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return self.ue_first_processor().process(self.session, PLAINTEXT)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(invoke, range(workers)))
        self.assertTrue(all(result.accepted for result in results))
        outputs = {result.record_bytes for result in results}
        self.assertEqual(len(outputs), 1)
        self.assertEqual(
            sum(
                result.disposition is UEFirstRecordDispositionV2.PREPARED_NEW
                for result in results
            ),
            1,
        )

    def test_parallel_processes_recover_one_exact_wire_record(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_outbox_prepare_worker,
                args=(
                    str(self.outbox_path),
                    self.session,
                    PLAINTEXT,
                    start,
                    output,
                ),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertTrue(all(result[1] is True for result in results), results)
        self.assertEqual(len({result[3] for result in results}), 1)
        self.assertEqual(
            sum(result[2] == UEFirstRecordDispositionV2.PREPARED_NEW.value for result in results),
            1,
        )

    def test_expired_session_and_new_record_after_deadline_fail_closed(self) -> None:
        expired_clock = GrantClock()
        expired_clock.value = self.session.session_expiry + 1
        expired = self.ue_first_processor(clock=expired_clock).process(
            self.session,
            PLAINTEXT,
        )
        self.assertFalse(expired.accepted)
        self.assertEqual(expired.failures, ("session_expired",))

        deadline_clock = GrantClock()
        deadline_clock.value = self.session.activation_deadline + 1
        after_deadline = self.ue_first_processor(clock=deadline_clock).process(
            self.session,
            PLAINTEXT,
        )
        self.assertFalse(after_deadline.accepted)
        self.assertEqual(
            after_deadline.failures,
            ("activation_deadline_expired",),
        )

    def test_sqlite_identity_schema_and_corruption_are_checked(self) -> None:
        self.assertEqual(APPLICATION_ID, 0x5051534F)
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(self.outbox_path.stat().st_mode & 0o777, 0o600)
        self.prepare()
        connection = sqlite3.connect(self.outbox_path)
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE first_record_outbox SET record_digest = ?",
                (fixed(b"corrupt-record-digest"),),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(FirstRecordOutboxIntegrityError):
            self.outbox.load(self.session.session_id)


class FGSFirstApplicationTests(FirstApplicationFixture):
    def test_valid_record_activates_then_releases_plaintext_once(self) -> None:
        prepared = self.prepare()
        delivery_store = InMemoryFirstApplicationDeliveryStoreV2()
        processor = self.fgs_first_processor(delivery_store=delivery_store)
        first = processor.process(prepared.record_bytes)
        retry = processor.process(prepared.record_bytes)
        self.assertTrue(first.accepted, first.failures)
        self.assertIs(first.disposition, FGSFirstRecordDispositionV2.DELIVERED)
        assert first.delivery is not None
        self.assertEqual(first.delivery.plaintext, PLAINTEXT)
        self.assertIs(
            self.store.lookup_session(self.session.session_id).state,  # type: ignore[union-attr]
            GrantStateV2.CONSUMED_ACTIVE,
        )
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_DELIVERED,
        )
        self.assertIsNone(retry.delivery)

    def test_parallel_exact_record_releases_one_delivery_capability(self) -> None:
        prepared = self.prepare()
        processor = self.fgs_first_processor(
            delivery_store=InMemoryFirstApplicationDeliveryStoreV2()
        )
        workers = 16
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return processor.process(prepared.record_bytes)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(invoke, range(workers)))
        self.assertTrue(all(result.accepted for result in results))
        self.assertEqual(
            sum(
                result.disposition is FGSFirstRecordDispositionV2.DELIVERED
                for result in results
            ),
            1,
        )
        self.assertEqual(sum(result.delivery is not None for result in results), 1)

    def test_corrupt_ciphertext_never_releases_plaintext_and_exact_retry_works(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        changed = bytearray(prepared.record.ciphertext)
        changed[-1] ^= 1
        corrupt_record = replace(prepared.record, ciphertext=bytes(changed))
        processor = self.fgs_first_processor(
            delivery_store=InMemoryFirstApplicationDeliveryStoreV2()
        )
        corrupt = processor.process(encode_first_application_record(corrupt_record))
        self.assertFalse(corrupt.accepted)
        self.assertTrue(
            corrupt.failures[0].startswith(
                "activation:pre_activation_check:"
            )
        )
        self.assertIsNone(corrupt.delivery)
        pending = self.store.lookup_session(self.session.session_id)
        assert pending is not None
        self.assertIs(pending.state, GrantStateV2.CONSUMED_PENDING_CONFIRM)
        recovered = processor.process(prepared.record_bytes)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(
            recovered.disposition,
            FGSFirstRecordDispositionV2.DELIVERED,
        )

    def test_flow_header_substitution_rejects_before_activation(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        mismatched = replace(
            prepared.record,
            response_digest=fixed(b"other-response"),
        )
        with self.assertRaisesRegex(
            ValueError,
            "activation and record header differ",
        ):
            encode_first_application_record(mismatched)
        pending = self.store.lookup_session(self.session.session_id)
        assert pending is not None
        self.assertIs(pending.state, GrantStateV2.CONSUMED_PENDING_CONFIRM)

    def test_second_authenticated_sequence_zero_record_is_rejected(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        delivery_store = InMemoryFirstApplicationDeliveryStoreV2()
        processor = self.fgs_first_processor(delivery_store=delivery_store)
        first = processor.process(prepared.record_bytes)
        self.assertTrue(first.accepted, first.failures)
        prototype = replace(prepared.record, ciphertext=b"placeholder")
        ciphertext = self.application_protection.seal(
            self.session.application_key,
            nonce_context=derive_first_application_nonce_context(
                self.session.suite_id,
                self.session.session_id,
            ),
            aad=derive_first_application_aad(prototype),
            plaintext=b"competing authenticated operation",
        )
        competing = replace(prepared.record, ciphertext=ciphertext)
        rejected = processor.process(encode_first_application_record(competing))
        self.assertFalse(rejected.accepted)
        self.assertEqual(rejected.failures, ("delivery_conflict",))
        self.assertIsNone(rejected.delivery)

    def test_suite_mismatch_and_delivery_uncertainty_fail_closed(self) -> None:
        prepared = self.prepare()
        wrong_suite = ApplicationProtectionTestBackend()
        wrong_suite.suite_id = 7
        mismatch = self.fgs_first_processor(
            protection_backend=wrong_suite
        ).process(prepared.record_bytes)
        self.assertFalse(mismatch.accepted)
        self.assertEqual(
            mismatch.failures,
            ("application_protection_suite_mismatch",),
        )

        for mode in ("raise", "wrong_type", "mutate"):
            with self.subTest(mode=mode):
                uncertain = self.fgs_first_processor(
                    delivery_store=BrokenDeliveryStore(mode)
                ).process(prepared.record_bytes)
                self.assertFalse(uncertain.accepted)
                self.assertIs(
                    uncertain.disposition,
                    FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                )
                self.assertIsNone(uncertain.delivery)

    def test_claims_remain_non_production(self) -> None:
        claims = first_application_checkpoint_manifest()["claim_boundary"]
        self.assertTrue(claims["canonical_first_application_record_implemented"])
        self.assertTrue(claims["fgs_one_time_delivery_capability_implemented"])
        self.assertTrue(claims["fgs_delivery_store_durable_or_distributed"])
        self.assertTrue(
            claims[
                "fgs_delivery_store_single_host_durable_reference_implemented"
            ]
        )
        self.assertFalse(claims["fgs_delivery_store_distributed"])
        self.assertTrue(
            claims["fgs_protected_plaintext_inbox_reference_implemented"]
        )
        self.assertTrue(
            claims["fgs_pending_inbox_restart_recovery_implemented"]
        )
        self.assertTrue(claims["application_apply_once_contract_implemented"])
        self.assertFalse(claims["activation_and_delivery_same_transaction"])
        self.assertFalse(claims["external_side_effect_exactly_once"])
        self.assertFalse(claims["production_aead_instantiated"])
        self.assertFalse(claims["production_ready"])
        self.assertEqual(FIRST_APPLICATION_SEQUENCE, 0)


if __name__ == "__main__":
    unittest.main()
