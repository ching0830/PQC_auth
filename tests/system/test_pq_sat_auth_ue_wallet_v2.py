from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.access import (
    derive_attempt_id,
    derive_request_digest,
    encode_access_accept,
    encode_access_request,
)
from pq_sat_auth.v2.storage.sqlite_wallet import (
    APPLICATION_ID,
    MAX_RECORD_BYTES,
    SCHEMA_VERSION,
    SQLiteUEWalletStoreV2,
    UEWalletConflictError,
    UEWalletIntegrityError,
    decode_wallet_record,
    encode_wallet_record,
    sqlite_ue_wallet_manifest,
)
from pq_sat_auth.v2.wallet import (
    PRODUCTION_READY,
    UEWalletAccessProcessorV2,
    UEWalletProcessDispositionV2,
    UEWalletRecordV2,
    UEWalletStateV2,
    UEWalletTransitionKindV2,
    UEWalletTransitionV2,
)
from tests.system.test_pq_sat_auth_grant_v2 import GrantClock
from tests.system.test_pq_sat_auth_processor_v2 import fixed
from tests.system.test_pq_sat_auth_ue_v2 import UEAccessAcceptFixture


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_ue_wallet_v0_2.json"
TEST_PROTECTION_KEY = hashlib.sha256(b"test-only-wallet-protection-key").digest()


class WalletProtectionTestBackend:
    production_ready = False

    def __init__(
        self,
        key: bytes = TEST_PROTECTION_KEY,
        *,
        protection_id: str = "TEST-ONLY-XOR-HMAC-SHA256/v1",
    ) -> None:
        self.key = key
        self.protection_id = protection_id
        self.invalid_seal = False
        self.invalid_open = False
        self.broken_seal = False
        self.broken_open = False

    def _stream(self, aad: bytes, length: int) -> bytes:
        return hashlib.shake_256(
            b"TEST-ONLY/UE-WALLET-STREAM/" + self.key + aad
        ).digest(length)

    def seal(self, plaintext: bytes, *, aad: bytes) -> bytes:
        if self.broken_seal:
            raise RuntimeError("test wallet seal failed")
        if self.invalid_seal:
            return b""  # type: ignore[return-value]
        stream = self._stream(aad, len(plaintext))
        body = bytes(left ^ right for left, right in zip(plaintext, stream))
        tag = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        return tag + body

    def open(self, protected_record: bytes, *, aad: bytes) -> bytes:
        if self.broken_open:
            raise RuntimeError("test wallet open failed")
        if self.invalid_open:
            return b""  # type: ignore[return-value]
        if len(protected_record) <= hashlib.sha256().digest_size:
            raise ValueError("test wallet record is truncated")
        tag = protected_record[: hashlib.sha256().digest_size]
        body = protected_record[hashlib.sha256().digest_size :]
        expected = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("test wallet record authentication failed")
        stream = self._stream(aad, len(body))
        return bytes(left ^ right for left, right in zip(body, stream))


class RaiseAfterAcceptWallet:
    def __init__(self, delegate: SQLiteUEWalletStoreV2) -> None:
        self.delegate = delegate

    def prepare(self, attempt):
        return self.delegate.prepare(attempt)

    def load(self, use_key):
        return self.delegate.load(use_key)

    def accept(self, attempt, response_bytes, session):
        self.delegate.accept(attempt, response_bytes, session)
        raise OSError("simulated lost commit acknowledgement")


class MutatingTransitionWallet(RaiseAfterAcceptWallet):
    def accept(self, attempt, response_bytes, session):
        transition = self.delegate.accept(attempt, response_bytes, session)
        assert transition.record.session is not None
        changed_session = replace(
            transition.record.session,
            application_key=fixed(b"mutated-application-key"),
        )
        return UEWalletTransitionV2(
            transition.kind,
            replace(transition.record, session=changed_session),
        )


class NeverCalledResponseProcessor:
    def process(self, encoded_response, attempt):
        raise AssertionError("accepted wallet recovery called response processor")


class BrokenResponseProcessor:
    def __init__(self, *, wrong_type: bool = False) -> None:
        self.wrong_type = wrong_type

    def process(self, encoded_response, attempt):
        if self.wrong_type:
            return object()
        raise RuntimeError("response processor failed")


def _prepare_process_worker(
    path: str,
    attempt,
    start,
    output,
) -> None:
    try:
        store = SQLiteUEWalletStoreV2(
            Path(path),
            WalletProtectionTestBackend(),
            busy_timeout_ms=20_000,
        )
        start.wait(10)
        result = store.prepare(attempt)
        output.put(("ok", result.kind.value))
    except Exception as error:
        output.put(("error", f"{type(error).__name__}:{error}"))


def _accept_then_exit_worker(
    path: str,
    attempt,
    response_bytes: bytes,
    session,
) -> None:
    store = SQLiteUEWalletStoreV2(
        Path(path),
        WalletProtectionTestBackend(),
        busy_timeout_ms=20_000,
    )
    store.accept(attempt, response_bytes, session)
    # Deliberately bypass Python cleanup after the SQLite commit returns.
    os._exit(17)


class UEWalletFixture(UEAccessAcceptFixture):
    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.wallet_path = Path(self.temporary.name) / "ue-wallet.sqlite3"
        self.wallet_protection = WalletProtectionTestBackend()
        self.wallet_store = SQLiteUEWalletStoreV2(
            self.wallet_path,
            self.wallet_protection,
        )
        self.use_key = self.grant_record.identity.use_key

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def accepted_session(self):
        result = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assertTrue(result.accepted, result.failures)
        assert result.session is not None
        return result.session

    def wallet_processor(self, *, wallet=None, response_processor=None, clock=None):
        return UEWalletAccessProcessorV2(
            wallet=self.wallet_store if wallet is None else wallet,
            response_processor=(
                self.ue_processor()
                if response_processor is None
                else response_processor
            ),
            clock=self.ue_clock if clock is None else clock,
        )


class UEWalletCodecTests(UEWalletFixture):
    def test_prepared_and_accepted_records_round_trip_canonically(self) -> None:
        prepared = UEWalletRecordV2(
            UEWalletStateV2.PREPARED,
            1,
            self.attempt_state,
        )
        encoded = encode_wallet_record(prepared)
        self.assertEqual(decode_wallet_record(encoded), prepared)
        self.assertEqual(encode_wallet_record(decode_wallet_record(encoded)), encoded)

        accepted = UEWalletRecordV2(
            UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION,
            2,
            self.attempt_state,
            self.response_bytes,
            self.accepted_session(),
        )
        encoded_accepted = encode_wallet_record(accepted)
        self.assertEqual(decode_wallet_record(encoded_accepted), accepted)
        self.assertEqual(
            hashlib.sha256(encoded_accepted).hexdigest(),
            "7cdd45ab20c7ff675c25a2bfae86bd4987e807cff130bc5408913ec56563aead",
        )

        shortened_attempt = replace(
            self.attempt_state,
            configuration=replace(
                self.attempt_state.configuration,
                valid_until=self.response.session_expiry - 1,
            ),
        )
        with self.assertRaisesRegex(
            ValueError,
            "response session exceeds authenticated validity",
        ):
            replace(accepted, attempt=shortened_attempt).validate()

    def test_record_decoder_rejects_alternate_or_unknown_encodings(self) -> None:
        prepared = UEWalletRecordV2(
            UEWalletStateV2.PREPARED,
            1,
            self.attempt_state,
        )
        encoded = encode_wallet_record(prepared)
        value = json.loads(encoded)

        value["unknown"] = 1
        with self.assertRaises(ValueError):
            decode_wallet_record(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )

        with self.assertRaises(UEWalletIntegrityError):
            decode_wallet_record(b" " + encoded)
        with self.assertRaises(UEWalletIntegrityError):
            decode_wallet_record(encoded + b"\n")
        with self.assertRaisesRegex(
            UEWalletIntegrityError,
            "exceeds the size bound",
        ):
            decode_wallet_record(b"x" * (MAX_RECORD_BYTES + 1))


class SQLiteUEWalletStoreTests(UEWalletFixture):
    def test_manifest_and_store_claim_boundary(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            sqlite_ue_wallet_manifest(),
        )
        self.assertFalse(PRODUCTION_READY)
        self.assertFalse(self.wallet_store.production_ready)
        self.assertTrue(self.wallet_store.durable_reference)
        self.assertFalse(self.wallet_store.distributed)

    def test_prepare_is_exact_idempotent_and_restart_recoverable(self) -> None:
        created = self.wallet_store.prepare(self.attempt_state)
        self.assertIs(created.kind, UEWalletTransitionKindV2.CREATED)
        self.assertIs(created.record.state, UEWalletStateV2.PREPARED)

        retry = self.wallet_store.prepare(self.attempt_state)
        self.assertIs(retry.kind, UEWalletTransitionKindV2.EXISTING)
        self.assertEqual(retry.record, created.record)

        with sqlite3.connect(self.wallet_path) as connection:
            row = connection.execute(
                "SELECT protected_record FROM ue_wallet_records WHERE use_key = ?",
                (self.use_key,),
            ).fetchone()
        assert row is not None
        protected = bytes(row[0])
        self.assertNotIn(self.attempt_state.request_bytes, protected)
        self.assertNotIn(self.attempt_state.ue_kem_secret_key, protected)

        reopened = SQLiteUEWalletStoreV2(
            self.wallet_path,
            WalletProtectionTestBackend(),
        )
        self.assertEqual(reopened.load(self.use_key), created.record)

    def test_committed_accept_survives_abrupt_process_exit(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        session = self.accepted_session()
        context = multiprocessing.get_context("fork")
        process = context.Process(
            target=_accept_then_exit_worker,
            args=(
                str(self.wallet_path),
                self.attempt_state,
                self.response_bytes,
                session,
            ),
        )
        process.start()
        process.join(20)
        self.assertEqual(process.exitcode, 17)

        reopened = SQLiteUEWalletStoreV2(
            self.wallet_path,
            WalletProtectionTestBackend(),
        )
        record = reopened.load(self.use_key)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertIs(
            record.state,
            UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION,
        )
        self.assertEqual(record.session, session)
        reopened.integrity_check()

    def test_same_ticket_different_attempt_is_rejected(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        request = replace(
            self.validated.request,
            attempt_nonce=hashlib.sha256(b"second-attempt").digest()[:16],
        )
        request_bytes = encode_access_request(request)
        request_digest = derive_request_digest(request)
        changed = replace(
            self.attempt_state,
            request_bytes=request_bytes,
            request_digest=request_digest,
            attempt_id=derive_attempt_id(self.use_key, request_digest),
        )
        with self.assertRaises(UEWalletConflictError):
            self.wallet_store.prepare(changed)
        self.assertEqual(
            self.wallet_store.load(self.use_key).attempt,
            self.attempt_state,
        )

    def test_accept_is_atomic_idempotent_and_restart_recoverable(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        session = self.accepted_session()
        created = self.wallet_store.accept(
            self.attempt_state,
            self.response_bytes,
            session,
        )
        self.assertIs(created.kind, UEWalletTransitionKindV2.CREATED)
        self.assertIs(
            created.record.state,
            UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION,
        )

        retry = self.wallet_store.accept(
            self.attempt_state,
            self.response_bytes,
            session,
        )
        self.assertIs(retry.kind, UEWalletTransitionKindV2.EXISTING)
        self.assertEqual(retry.record, created.record)

        reopened = SQLiteUEWalletStoreV2(
            self.wallet_path,
            WalletProtectionTestBackend(),
        )
        self.assertEqual(reopened.load(self.use_key), created.record)

    def test_accept_requires_prepared_and_rejects_conflicting_session(self) -> None:
        session = self.accepted_session()
        with self.assertRaises(UEWalletConflictError):
            self.wallet_store.accept(
                self.attempt_state,
                self.response_bytes,
                session,
            )

        self.wallet_store.prepare(self.attempt_state)
        self.wallet_store.accept(
            self.attempt_state,
            self.response_bytes,
            session,
        )
        changed = replace(
            session,
            application_key=fixed(b"different-application-key"),
        )
        with self.assertRaises(UEWalletConflictError):
            self.wallet_store.accept(
                self.attempt_state,
                self.response_bytes,
                changed,
            )

    def test_protected_record_and_row_metadata_mutations_fail_closed(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        with sqlite3.connect(self.wallet_path) as connection:
            row = connection.execute(
                "SELECT protected_record FROM ue_wallet_records WHERE use_key = ?",
                (self.use_key,),
            ).fetchone()
            assert row is not None
            protected = bytes(row[0])
            changed = protected[:-1] + bytes((protected[-1] ^ 1,))
            connection.execute(
                "UPDATE ue_wallet_records SET protected_record = ? "
                "WHERE use_key = ?",
                (changed, self.use_key),
            )
        with self.assertRaises(UEWalletIntegrityError):
            self.wallet_store.load(self.use_key)

        fresh_path = Path(self.temporary.name) / "metadata-wallet.sqlite3"
        fresh = SQLiteUEWalletStoreV2(
            fresh_path,
            WalletProtectionTestBackend(),
        )
        fresh.prepare(self.attempt_state)
        with sqlite3.connect(fresh_path) as connection:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE ue_wallet_records SET state = 2, revision = 2 "
                "WHERE use_key = ?",
                (self.use_key,),
            )
        with self.assertRaises(UEWalletIntegrityError):
            fresh.load(self.use_key)

    def test_protection_backend_identity_and_failures_are_rejected(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        wrong_identity = SQLiteUEWalletStoreV2(
            self.wallet_path,
            WalletProtectionTestBackend(protection_id="TEST-ONLY/OTHER"),
        )
        with self.assertRaises(UEWalletIntegrityError):
            wrong_identity.load(self.use_key)

        self.wallet_protection.broken_open = True
        with self.assertRaises(UEWalletIntegrityError):
            self.wallet_store.load(self.use_key)
        self.wallet_protection.broken_open = False
        self.wallet_protection.invalid_open = True
        with self.assertRaises(UEWalletIntegrityError):
            self.wallet_store.load(self.use_key)

        bad_path = Path(self.temporary.name) / "bad-protector.sqlite3"
        invalid = WalletProtectionTestBackend()
        invalid.invalid_seal = True
        bad_store = SQLiteUEWalletStoreV2(bad_path, invalid)
        with self.assertRaises(UEWalletIntegrityError):
            bad_store.prepare(self.attempt_state)

    def test_database_application_and_schema_identity_are_enforced(self) -> None:
        wrong_app = Path(self.temporary.name) / "wrong-app.sqlite3"
        with sqlite3.connect(wrong_app) as connection:
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID + 1}")
        with self.assertRaises(UEWalletIntegrityError):
            SQLiteUEWalletStoreV2(wrong_app, WalletProtectionTestBackend())

        wrong_version = Path(self.temporary.name) / "wrong-version.sqlite3"
        with sqlite3.connect(wrong_version) as connection:
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        with self.assertRaises(UEWalletIntegrityError):
            SQLiteUEWalletStoreV2(wrong_version, WalletProtectionTestBackend())

    def test_parallel_threads_have_one_prepare_winner(self) -> None:
        workers = 16
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return self.wallet_store.prepare(self.attempt_state).kind

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(invoke, range(workers)))
        self.assertEqual(outcomes.count(UEWalletTransitionKindV2.CREATED), 1)
        self.assertEqual(outcomes.count(UEWalletTransitionKindV2.EXISTING), 15)

    def test_parallel_processes_have_one_prepare_winner(self) -> None:
        context = multiprocessing.get_context("fork")
        start = context.Event()
        output = context.Queue()
        workers = 6
        processes = [
            context.Process(
                target=_prepare_process_worker,
                args=(
                    str(self.wallet_path),
                    self.attempt_state,
                    start,
                    output,
                ),
            )
            for _ in range(workers)
        ]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        outcomes = [output.get(timeout=2) for _ in processes]
        self.assertTrue(all(status == "ok" for status, _ in outcomes), outcomes)
        kinds = [value for _, value in outcomes]
        self.assertEqual(kinds.count(UEWalletTransitionKindV2.CREATED.value), 1)
        self.assertEqual(kinds.count(UEWalletTransitionKindV2.EXISTING.value), 5)


class UEWalletAccessProcessorTests(UEWalletFixture):
    def test_new_response_commits_before_session_release(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        result = self.wallet_processor().process(
            self.use_key,
            self.response_bytes,
        )
        self.assertTrue(result.accepted, result.failures)
        self.assertIs(
            result.disposition,
            UEWalletProcessDispositionV2.ACCEPTED_NEW,
        )
        record = self.wallet_store.load(self.use_key)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(result.session, record.session)
        self.assertEqual(record.response_bytes, self.response_bytes)

    def test_restart_recovers_exact_session_without_reprocessing_m2(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        first = self.wallet_processor().process(
            self.use_key,
            self.response_bytes,
        )
        self.assertTrue(first.accepted, first.failures)

        reopened = SQLiteUEWalletStoreV2(
            self.wallet_path,
            WalletProtectionTestBackend(),
        )
        recovered = self.wallet_processor(
            wallet=reopened,
            response_processor=NeverCalledResponseProcessor(),
        ).process(self.use_key, self.response_bytes)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(
            recovered.disposition,
            UEWalletProcessDispositionV2.ACCEPTED_RECOVERED,
        )
        self.assertEqual(recovered.session, first.session)

    def test_invalid_response_never_changes_prepared_record(self) -> None:
        prepared = self.wallet_store.prepare(self.attempt_state).record
        result = self.wallet_processor().process(
            self.use_key,
            self.response_bytes[:-1],
        )
        self.assertFalse(result.accepted)
        self.assertIs(
            result.disposition,
            UEWalletProcessDispositionV2.REJECTED,
        )
        self.assertIsNone(result.session)
        self.assertEqual(self.wallet_store.load(self.use_key), prepared)

    def test_response_processor_exception_and_wrong_type_fail_closed(self) -> None:
        prepared = self.wallet_store.prepare(self.attempt_state).record
        for processor in (
            BrokenResponseProcessor(),
            BrokenResponseProcessor(wrong_type=True),
        ):
            with self.subTest(processor=processor):
                result = self.wallet_processor(
                    response_processor=processor
                ).process(self.use_key, self.response_bytes)
                self.assertFalse(result.accepted)
                self.assertIsNone(result.session)
                self.assertEqual(self.wallet_store.load(self.use_key), prepared)

    def test_lost_commit_ack_releases_nothing_and_retry_recovers(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        uncertain = self.wallet_processor(
            wallet=RaiseAfterAcceptWallet(self.wallet_store)
        ).process(self.use_key, self.response_bytes)
        self.assertFalse(uncertain.accepted)
        self.assertIs(
            uncertain.disposition,
            UEWalletProcessDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIsNone(uncertain.session)

        recovered = self.wallet_processor(
            response_processor=NeverCalledResponseProcessor()
        ).process(self.use_key, self.response_bytes)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(
            recovered.disposition,
            UEWalletProcessDispositionV2.ACCEPTED_RECOVERED,
        )

    def test_mutating_commit_output_is_uncertain_and_recoverable(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        uncertain = self.wallet_processor(
            wallet=MutatingTransitionWallet(self.wallet_store)
        ).process(self.use_key, self.response_bytes)
        self.assertFalse(uncertain.accepted)
        self.assertIs(
            uncertain.disposition,
            UEWalletProcessDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIsNone(uncertain.session)

        recovered = self.wallet_processor(
            response_processor=NeverCalledResponseProcessor()
        ).process(self.use_key, self.response_bytes)
        self.assertTrue(recovered.accepted, recovered.failures)

    def test_recovery_rejects_wrong_response_and_expired_deadline(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        accepted = self.wallet_processor().process(
            self.use_key,
            self.response_bytes,
        )
        self.assertTrue(accepted.accepted, accepted.failures)
        assert accepted.session is not None

        wrong = self.wallet_processor(
            response_processor=NeverCalledResponseProcessor()
        ).process(
            self.use_key,
            encode_access_accept(
                replace(self.response, fgs_authenticator=b"x")
            ),
        )
        self.assertFalse(wrong.accepted)
        self.assertIsNone(wrong.session)

        expired = self.wallet_processor(
            response_processor=NeverCalledResponseProcessor(),
            clock=GrantClock(accepted.session.activation_deadline + 1),
        ).process(self.use_key, self.response_bytes)
        self.assertFalse(expired.accepted)
        self.assertEqual(
            expired.failures,
            ("wallet_activation_deadline_expired",),
        )
        self.assertIsNone(expired.session)

    def test_parallel_exact_m2_has_one_wallet_transition(self) -> None:
        self.wallet_store.prepare(self.attempt_state)
        processor = self.wallet_processor()
        workers = 12
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return processor.process(self.use_key, self.response_bytes)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(invoke, range(workers)))
        self.assertTrue(all(result.accepted for result in outcomes))
        dispositions = [result.disposition for result in outcomes]
        self.assertEqual(
            dispositions.count(UEWalletProcessDispositionV2.ACCEPTED_NEW),
            1,
        )
        self.assertEqual(
            dispositions.count(UEWalletProcessDispositionV2.ACCEPTED_RECOVERED),
            11,
        )
        sessions = [result.session for result in outcomes]
        self.assertTrue(all(session == sessions[0] for session in sessions))


if __name__ == "__main__":
    unittest.main()
