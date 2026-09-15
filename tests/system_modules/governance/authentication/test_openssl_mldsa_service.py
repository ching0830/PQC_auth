from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pq_rbbc.contracts.system import (
    ContractError,
    KeyReference,
    KeyRole,
    SystemConfiguration,
    ThresholdPolicy,
)
from pq_rbbc.governance.authentication import (
    MLDSA65_SIGNATURE_BYTES,
    MLDSA65_STAGING_PROFILE,
    TRUST_REGISTRY_FILENAME,
    MLDSABackendError,
    OpenSSLMLDSA65NonThresholdSigner,
    PinnedOpenSSLMLDSA65,
    PinnedSystemGovernanceService,
    PinnedTrustRegistry,
    TrustedPublicKey,
    assemble_initialization_bundle,
    canonical_registry_bytes,
    mldsa65_spki_from_raw,
    publish_initialization,
    publish_issuer_grant,
    trust_registry_document,
)
from pq_rbbc.governance.issuer_authorization import (
    AuthenticatedIssuerGrant,
    IssuerGrant,
)
from pq_rbbc.governance.storage import SQLiteIssuerQuotaStore
from pq_rbbc.governance.system_init import AuthenticatedSystemInitialization


OPENSSL_ENV = "PQRBBC_TEST_OPENSSL"
OPENSSL_SHA256_ENV = "PQRBBC_TEST_OPENSSL_SHA256"
OPENSSL_VERSION_ENV = "PQRBBC_TEST_OPENSSL_VERSION"
ACVP_PROMPT_ENV = "PQRBBC_NIST_ACVP_MLDSA_PROMPT"
ACVP_EXPECTED_ENV = "PQRBBC_NIST_ACVP_MLDSA_EXPECTED"
ACVP_PROMPT_SHA256 = "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e"
ACVP_EXPECTED_SHA256 = "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6"


def _backend_from_environment() -> PinnedOpenSSLMLDSA65:
    values = tuple(
        os.environ.get(name)
        for name in (OPENSSL_ENV, OPENSSL_SHA256_ENV, OPENSSL_VERSION_ENV)
    )
    if not all(values):
        raise unittest.SkipTest(
            "exact OpenSSL path, SHA-256, and version were not provisioned"
        )
    return PinnedOpenSSLMLDSA65(
        values[0],
        expected_sha256=values[1],
        expected_version_line=values[2],
    )


def _run_key_command(executable: str, arguments: tuple[str, ...]) -> None:
    result = subprocess.run(
        (executable,) + arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": os.devnull},
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"test key command failed: {result.returncode}")


class RealMLDSAServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = _backend_from_environment()
        cls._temporary = tempfile.TemporaryDirectory(prefix="pqrbbc-s2-real-")
        cls.directory = Path(cls._temporary.name)
        cls.config_private = cls.directory / "configuration-private.pem"
        cls.grant_private = cls.directory / "grant-private.pem"
        executable = os.environ[OPENSSL_ENV]
        for private_path in (cls.config_private, cls.grant_private):
            _run_key_command(
                executable,
                (
                    "genpkey",
                    "-algorithm",
                    "ML-DSA-65",
                    "-out",
                    os.fspath(private_path),
                ),
            )
            private_path.chmod(0o600)
        cls.config_public = cls.directory / "configuration.der"
        cls.grant_public = cls.directory / "issuer-authorization.der"
        for private_path, public_path in (
            (cls.config_private, cls.config_public),
            (cls.grant_private, cls.grant_public),
        ):
            _run_key_command(
                executable,
                (
                    "pkey",
                    "-in",
                    os.fspath(private_path),
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    os.fspath(public_path),
                ),
            )
            public_path.chmod(0o644)

        config_public = cls.config_public.read_bytes()
        grant_public = cls.grant_public.read_bytes()
        config_entry = TrustedPublicKey(
            reference=KeyReference(
                KeyRole.FEDERATION_CONFIGURATION,
                hashlib.sha256(b"configuration-key-id" + config_public).digest(),
                hashlib.sha256(config_public).digest(),
            ),
            profile=MLDSA65_STAGING_PROFILE,
            public_key_der=config_public,
            source_filename=cls.config_public.name,
        )
        grant_entry = TrustedPublicKey(
            reference=KeyReference(
                KeyRole.ISSUER_AUTHORIZATION,
                hashlib.sha256(b"grant-key-id" + grant_public).digest(),
                hashlib.sha256(grant_public).digest(),
            ),
            profile=MLDSA65_STAGING_PROFILE,
            public_key_der=grant_public,
            source_filename=cls.grant_public.name,
        )
        manifest = trust_registry_document((config_entry, grant_entry))
        registry_path = cls.directory / TRUST_REGISTRY_FILENAME
        registry_path.write_bytes(canonical_registry_bytes(manifest))
        registry_path.chmod(0o644)
        cls.registry = PinnedTrustRegistry.load(cls.directory)
        cls.config_signer = OpenSSLMLDSA65NonThresholdSigner(
            cls.backend,
            config_entry.reference,
            config_public,
            cls.config_private,
        )
        cls.grant_signer = OpenSSLMLDSA65NonThresholdSigner(
            cls.backend,
            grant_entry.reference,
            grant_public,
            cls.grant_private,
        )
        cls.configuration = SystemConfiguration(
            protocol_version=1,
            epoch=19,
            domain=hashlib.sha256(b"S2 federation domain").digest(),
            policy_digest=hashlib.sha256(b"S2 policy").digest(),
            expiry_bucket=200,
            oa_key_id=hashlib.sha256(b"T opening encryption key").digest(),
            issuer_key_id=hashlib.sha256(b"B issuer verification key").digest(),
        )
        cls.opening_authorization = KeyReference(
            KeyRole.OPENING_AUTHORIZATION,
            hashlib.sha256(b"opening authorization id").digest(),
            hashlib.sha256(b"opening authorization public bytes").digest(),
        )
        cls.issuer_verification = KeyReference(
            KeyRole.ISSUER_VERIFICATION,
            cls.configuration.issuer_key_id,
            hashlib.sha256(b"B issuer verification public bytes").digest(),
        )
        cls.opening_encryption = KeyReference(
            KeyRole.OPENING_ENCRYPTION,
            cls.configuration.oa_key_id,
            hashlib.sha256(b"T opening encryption public bytes").digest(),
        )
        cls.bundle = assemble_initialization_bundle(
            registry=cls.registry,
            configuration=cls.configuration,
            common_parameters_digest=hashlib.sha256(
                b"B issuance relation parameters"
            ).digest(),
            federation_policy=ThresholdPolicy(3, 2),
            opening_policy=ThresholdPolicy(4, 3),
            opening_authorization_key=cls.opening_authorization,
            issuer_verification_key=cls.issuer_verification,
            opening_encryption_key=cls.opening_encryption,
        )
        cls.initialization = publish_initialization(cls.bundle, cls.config_signer)
        cls.grant = IssuerGrant(
            ctx=cls.bundle.ctx,
            protocol_version=cls.configuration.protocol_version,
            epoch=cls.configuration.epoch,
            policy_digest=cls.configuration.policy_digest,
            issuer_key_id=cls.configuration.issuer_key_id,
            issuer_authorization_key_id=grant_entry.reference.key_id,
            quota=2,
            not_before=100,
            expiry=200,
            grant_identifier=hashlib.sha256(b"S2 real grant").digest(),
        )
        cls.authenticated_grant = publish_issuer_grant(cls.grant, cls.grant_signer)
        cls.service = PinnedSystemGovernanceService(cls.registry, cls.backend)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_real_bundle_and_grant_authentication_reaches_persistent_quota(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pqrbbc-s2-quota-") as directory:
            database = Path(directory) / "quota.sqlite3"
            store = SQLiteIssuerQuotaStore(database)
            first = self.service.authorize_issuance(
                self.initialization.encode(),
                self.authenticated_grant.encode(),
                quota_store=store,
                issuer_sid=b"real-sid-1",
                now=150,
            )
            self.assertTrue(first.accepted)
            self.assertEqual(first.remaining_quota, 1)
            reopened = SQLiteIssuerQuotaStore(database)
            replay = self.service.authorize_issuance(
                self.initialization.encode(),
                self.authenticated_grant.encode(),
                quota_store=reopened,
                issuer_sid=b"real-sid-1",
                now=150,
            )
            self.assertFalse(replay.accepted)
            self.assertEqual(replay.failures, ("quota_replay",))
            self.assertEqual(replay.remaining_quota, 1)

    def test_full_initialization_message_mutations_fail(self) -> None:
        mutations = (
            dataclasses.replace(
                self.bundle,
                configuration=dataclasses.replace(
                    self.configuration,
                    expiry_bucket=self.configuration.expiry_bucket + 1,
                ),
            ),
            dataclasses.replace(
                self.bundle,
                common_parameters_digest=hashlib.sha256(b"changed parameters").digest(),
            ),
            dataclasses.replace(
                self.bundle,
                opening_policy=ThresholdPolicy(5, 3),
            ),
            dataclasses.replace(
                self.bundle,
                keys=self.bundle.keys[:-1]
                + (
                    dataclasses.replace(
                        self.bundle.keys[-1],
                        public_key_digest=hashlib.sha256(
                            b"changed T opening key"
                        ).digest(),
                    ),
                ),
            ),
        )
        for bundle in mutations:
            with self.subTest(bundle_sha=bundle.sha256):
                forged = AuthenticatedSystemInitialization(
                    bundle, self.initialization.authentication
                )
                result = self.service.verify_initialization(forged.encode())
                self.assertFalse(result.accepted)
                self.assertIn("configuration_authentication_invalid", result.failures)

    def test_signature_and_grant_field_mutations_fail_without_consumption(self) -> None:
        changed_signature = bytearray(self.authenticated_grant.authentication)
        changed_signature[-1] ^= 1
        forged_signature = dataclasses.replace(
            self.authenticated_grant, authentication=bytes(changed_signature)
        )
        forged_grant = dataclasses.replace(self.grant, quota=3)
        forged_field = AuthenticatedIssuerGrant(
            forged_grant,
            KeyRole.ISSUER_AUTHORIZATION,
            self.authenticated_grant.authentication,
        )
        for forged in (forged_signature, forged_field):
            with self.subTest(kind=type(forged).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    store = SQLiteIssuerQuotaStore(Path(directory) / "quota.sqlite3")
                    rejected = self.service.authorize_issuance(
                        self.initialization.encode(),
                        forged.encode(),
                        quota_store=store,
                        issuer_sid=b"not-consumed",
                        now=150,
                    )
                    self.assertFalse(rejected.accepted)
                    accepted = self.service.authorize_issuance(
                        self.initialization.encode(),
                        self.authenticated_grant.encode(),
                        quota_store=store,
                        issuer_sid=b"not-consumed",
                        now=150,
                    )
                    self.assertTrue(accepted.accepted)
                    self.assertEqual(accepted.remaining_quota, 1)

    def test_initialization_signature_mutation_fails_without_consumption(self) -> None:
        signature = bytearray(self.initialization.authentication)
        signature[0] ^= 1
        forged = dataclasses.replace(self.initialization, authentication=bytes(signature))
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteIssuerQuotaStore(Path(directory) / "quota.sqlite3")
            rejected = self.service.authorize_issuance(
                forged.encode(),
                self.authenticated_grant.encode(),
                quota_store=store,
                issuer_sid=b"init-not-consumed",
                now=150,
            )
            self.assertFalse(rejected.accepted)
            accepted = self.service.authorize_issuance(
                self.initialization.encode(),
                self.authenticated_grant.encode(),
                quota_store=store,
                issuer_sid=b"init-not-consumed",
                now=150,
            )
            self.assertTrue(accepted.accepted)
            self.assertEqual(accepted.remaining_quota, 1)

    def test_configuration_and_grant_signer_roles_are_separate(self) -> None:
        with self.assertRaisesRegex(ContractError, "configuration signer"):
            publish_initialization(self.bundle, self.grant_signer)
        with self.assertRaisesRegex(ContractError, "wrong role"):
            publish_issuer_grant(self.grant, self.config_signer)
        with self.assertRaisesRegex(MLDSABackendError, "does not match"):
            OpenSSLMLDSA65NonThresholdSigner(
                self.backend,
                self.config_signer.key_reference,
                self.config_public.read_bytes(),
                self.grant_private,
            )

    def test_self_signed_unpinned_initialization_is_rejected(self) -> None:
        swapped_config = TrustedPublicKey(
            KeyReference(
                KeyRole.FEDERATION_CONFIGURATION,
                hashlib.sha256(b"attacker config id").digest(),
                hashlib.sha256(self.grant_public.read_bytes()).digest(),
            ),
            MLDSA65_STAGING_PROFILE,
            self.grant_public.read_bytes(),
            "attacker-config.der",
        )
        swapped_grant = TrustedPublicKey(
            KeyReference(
                KeyRole.ISSUER_AUTHORIZATION,
                hashlib.sha256(b"attacker grant id").digest(),
                hashlib.sha256(self.config_public.read_bytes()).digest(),
            ),
            MLDSA65_STAGING_PROFILE,
            self.config_public.read_bytes(),
            "attacker-grant.der",
        )
        attacker_registry = PinnedTrustRegistry((swapped_config, swapped_grant))
        attacker_signer = OpenSSLMLDSA65NonThresholdSigner(
            self.backend,
            swapped_config.reference,
            swapped_config.public_key_der,
            self.grant_private,
        )
        attacker_bundle = assemble_initialization_bundle(
            registry=attacker_registry,
            configuration=self.configuration,
            common_parameters_digest=self.bundle.common_parameters_digest,
            federation_policy=self.bundle.federation_policy,
            opening_policy=self.bundle.opening_policy,
            opening_authorization_key=self.opening_authorization,
            issuer_verification_key=self.issuer_verification,
            opening_encryption_key=self.opening_encryption,
        )
        attacker_initialization = publish_initialization(
            attacker_bundle, attacker_signer
        )
        result = self.service.verify_initialization(attacker_initialization.encode())
        self.assertFalse(result.accepted)
        self.assertEqual(result.failures, ("configuration_trust_anchor_mismatch",))

    def test_signed_bundle_with_unpinned_grant_key_is_rejected_as_initialization(self) -> None:
        replacement = KeyReference(
            KeyRole.ISSUER_AUTHORIZATION,
            hashlib.sha256(b"untrusted grant id").digest(),
            hashlib.sha256(b"untrusted grant public key").digest(),
        )
        bundle = dataclasses.replace(
            self.bundle,
            keys=(self.bundle.keys[0], replacement) + self.bundle.keys[2:],
        )
        initialization = publish_initialization(bundle, self.config_signer)
        result = self.service.verify_initialization(initialization.encode())
        self.assertFalse(result.accepted)
        self.assertEqual(
            result.failures, ("issuer_authorization_trust:TrustRegistryError",)
        )

    def test_request_api_has_no_trust_or_verified_bypass(self) -> None:
        verification_parameters = inspect.signature(
            self.service.verify_initialization
        ).parameters
        authorization_parameters = inspect.signature(
            self.service.authorize_issuance
        ).parameters
        forbidden = {
            "trusted_configuration_key",
            "verifier",
            "initialization_verifier",
            "grant_verifier",
            "verified",
        }
        self.assertTrue(forbidden.isdisjoint(verification_parameters))
        self.assertTrue(forbidden.isdisjoint(authorization_parameters))
        with self.assertRaises(TypeError):
            self.service.verify_initialization(
                self.initialization.encode(), verified=True
            )

    def test_backend_rejects_wrong_binary_digest_version_and_symlink(self) -> None:
        executable = os.environ[OPENSSL_ENV]
        digest = os.environ[OPENSSL_SHA256_ENV]
        version = os.environ[OPENSSL_VERSION_ENV]
        with self.assertRaisesRegex(MLDSABackendError, "digest mismatch"):
            PinnedOpenSSLMLDSA65(
                executable,
                expected_sha256="00" * 32,
                expected_version_line=version,
            )
        with self.assertRaisesRegex(MLDSABackendError, "version"):
            PinnedOpenSSLMLDSA65(
                executable,
                expected_sha256=digest,
                expected_version_line=version + " forged",
            )
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "openssl"
            link.symlink_to(executable)
            with self.assertRaisesRegex(MLDSABackendError, "safely open"):
                PinnedOpenSSLMLDSA65(
                    link,
                    expected_sha256=digest,
                    expected_version_line=version,
                )

    def test_backend_rechecks_executable_identity_for_every_operation(self) -> None:
        executable = Path(os.environ[OPENSSL_ENV])
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "openssl"
            shutil.copy2(executable, copy)
            backend = PinnedOpenSSLMLDSA65(
                copy,
                expected_sha256=os.environ[OPENSSL_SHA256_ENV],
                expected_version_line=os.environ[OPENSSL_VERSION_ENV],
            )
            replacement = Path(directory) / "replacement"
            replacement.write_bytes(b"not the pinned executable")
            replacement.chmod(0o700)
            os.replace(replacement, copy)
            with self.assertRaisesRegex(MLDSABackendError, "digest mismatch"):
                backend.validate_public_key(self.config_public.read_bytes())

    def test_public_key_signature_and_private_key_constraints_fail_closed(self) -> None:
        public = self.config_public.read_bytes()
        with self.assertRaisesRegex(MLDSABackendError, "DER length"):
            self.backend.validate_public_key(public + b"\x00")
        with self.assertRaisesRegex(MLDSABackendError, "not canonical"):
            self.backend.validate_public_key(bytes(len(public)))
        self.assertFalse(
            self.backend.verify(public, b"message", bytes(MLDSA65_SIGNATURE_BYTES))
        )
        self.assertFalse(
            self.backend.verify(
                public,
                self.initialization.authentication_message,
                self.initialization.authentication,
                context=b"wrong-application-context",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private.pem"
            private.write_bytes(self.config_private.read_bytes())
            private.chmod(0o644)
            with self.assertRaisesRegex(MLDSABackendError, "0600"):
                OpenSSLMLDSA65NonThresholdSigner(
                    self.backend,
                    self.config_signer.key_reference,
                    public,
                    private,
                )


class OfficialACVPMLDSA65Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = _backend_from_environment()
        prompt_path = os.environ.get(ACVP_PROMPT_ENV)
        expected_path = os.environ.get(ACVP_EXPECTED_ENV)
        if not prompt_path or not expected_path:
            raise unittest.SkipTest("exact NIST ACVP sample files were not provisioned")
        cls.prompt_bytes = Path(prompt_path).read_bytes()
        cls.expected_bytes = Path(expected_path).read_bytes()
        if hashlib.sha256(cls.prompt_bytes).hexdigest() != ACVP_PROMPT_SHA256:
            raise RuntimeError("NIST ACVP prompt file digest mismatch")
        if hashlib.sha256(cls.expected_bytes).hexdigest() != ACVP_EXPECTED_SHA256:
            raise RuntimeError("NIST ACVP expected-results file digest mismatch")
        cls.prompt = json.loads(cls.prompt_bytes)
        cls.expected = json.loads(cls.expected_bytes)

    def test_official_external_pure_valid_and_invalid_vectors(self) -> None:
        group = next(
            group for group in self.prompt["testGroups"] if group["tgId"] == 3
        )
        expected_group = next(
            group for group in self.expected["testGroups"] if group["tgId"] == 3
        )
        self.assertEqual(group["parameterSet"], "ML-DSA-65")
        self.assertEqual(group["signatureInterface"], "external")
        self.assertEqual(group["preHash"], "pure")
        expected_by_id = {
            test["tcId"]: test["testPassed"] for test in expected_group["tests"]
        }
        for test_id in (31, 33):
            with self.subTest(tcId=test_id):
                vector = next(
                    test for test in group["tests"] if test["tcId"] == test_id
                )
                result = self.backend.verify(
                    mldsa65_spki_from_raw(bytes.fromhex(vector["pk"])),
                    bytes.fromhex(vector["message"]),
                    bytes.fromhex(vector["signature"]),
                    context=bytes.fromhex(vector["context"]),
                )
                self.assertEqual(result, expected_by_id[test_id])


if __name__ == "__main__":
    unittest.main()
