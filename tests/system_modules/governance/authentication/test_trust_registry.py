from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from pq_rbbc.contracts.system import KeyReference, KeyRole
from pq_rbbc.governance.authentication import (
    MLDSA65_STAGING_PROFILE,
    TRUST_REGISTRY_FILENAME,
    TRUST_REGISTRY_FORMAT,
    PinnedTrustRegistry,
    TrustRegistryError,
    canonical_registry_bytes,
)


def _document(config_key: bytes, grant_key: bytes) -> dict[str, object]:
    return {
        "entries": [
            {
                "key_id": (b"C" * 32).hex(),
                "profile": MLDSA65_STAGING_PROFILE,
                "public_key_file": "configuration.der",
                "public_key_sha256": hashlib.sha256(config_key).hexdigest(),
                "role": "FEDERATION_CONFIGURATION",
            },
            {
                "key_id": (b"G" * 32).hex(),
                "profile": MLDSA65_STAGING_PROFILE,
                "public_key_file": "issuer-authorization.der",
                "public_key_sha256": hashlib.sha256(grant_key).hexdigest(),
                "role": "ISSUER_AUTHORIZATION",
            },
        ],
        "format": TRUST_REGISTRY_FORMAT,
        "schema_version": 1,
    }


def _write_registry(
    directory: Path,
    config_key: bytes = b"configuration-public-key",
    grant_key: bytes = b"grant-public-key",
    document: dict[str, object] | None = None,
) -> dict[str, object]:
    (directory / "configuration.der").write_bytes(config_key)
    (directory / "issuer-authorization.der").write_bytes(grant_key)
    (directory / "configuration.der").chmod(0o644)
    (directory / "issuer-authorization.der").chmod(0o644)
    value = _document(config_key, grant_key) if document is None else document
    (directory / TRUST_REGISTRY_FILENAME).write_bytes(
        canonical_registry_bytes(value)
    )
    (directory / TRUST_REGISTRY_FILENAME).chmod(0o644)
    return value


class PinnedTrustRegistryTests(unittest.TestCase):
    def test_loads_exact_registry_and_resolves_complete_reference(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            config_key = b"configuration-public-key"
            grant_key = b"grant-public-key"
            _write_registry(directory, config_key, grant_key)
            registry = PinnedTrustRegistry.load(directory)

            self.assertEqual(len(registry.entries), 2)
            entry = registry.trusted_key(KeyRole.FEDERATION_CONFIGURATION)
            self.assertEqual(entry.public_key_der, config_key)
            self.assertEqual(registry.resolve(entry.reference), entry)
            wrong_digest = KeyReference(
                role=entry.reference.role,
                key_id=entry.reference.key_id,
                public_key_digest=b"X" * 32,
            )
            with self.assertRaises(TrustRegistryError):
                registry.resolve(wrong_digest)

    def test_captured_key_is_not_reopened_after_load(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            _write_registry(directory)
            registry = PinnedTrustRegistry.load(directory)
            original = registry.trusted_key(
                KeyRole.FEDERATION_CONFIGURATION
            ).public_key_der
            (directory / "configuration.der").write_bytes(b"attacker replacement")
            self.assertEqual(
                registry.trusted_key(
                    KeyRole.FEDERATION_CONFIGURATION
                ).public_key_der,
                original,
            )

    def test_rejects_forged_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            document = _write_registry(directory)
            document["entries"][0]["public_key_sha256"] = (b"F" * 32).hex()
            (directory / TRUST_REGISTRY_FILENAME).write_bytes(
                canonical_registry_bytes(document)
            )
            with self.assertRaisesRegex(TrustRegistryError, "digest mismatch"):
                PinnedTrustRegistry.load(directory)

    def test_rejects_duplicate_json_member_even_with_valid_later_value(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            _write_registry(directory)
            encoded = (directory / TRUST_REGISTRY_FILENAME).read_text("ascii")
            forged = encoded.replace(
                '{"entries":',
                '{"format":"attacker","entries":',
                1,
            )
            (directory / TRUST_REGISTRY_FILENAME).write_text(forged, "ascii")
            with self.assertRaisesRegex(TrustRegistryError, "duplicate JSON member"):
                PinnedTrustRegistry.load(directory)

    def test_rejects_noncanonical_json_and_unknown_member(self) -> None:
        for mutation in ("trailing", "unknown"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as raw_directory:
                    directory = Path(raw_directory)
                    document = _write_registry(directory)
                    if mutation == "trailing":
                        path = directory / TRUST_REGISTRY_FILENAME
                        path.write_bytes(path.read_bytes() + b"\n")
                    else:
                        document["unexpected"] = True
                        (directory / TRUST_REGISTRY_FILENAME).write_bytes(
                            canonical_registry_bytes(document)
                        )
                    with self.assertRaises(TrustRegistryError):
                        PinnedTrustRegistry.load(directory)

    def test_rejects_role_order_profile_and_duplicate_material(self) -> None:
        mutations = ("order", "profile", "key_id", "key_bytes")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as raw_directory:
                    directory = Path(raw_directory)
                    document = _document(
                        b"configuration-public-key", b"grant-public-key"
                    )
                    if mutation == "order":
                        document["entries"].reverse()
                    elif mutation == "profile":
                        document["entries"][0]["profile"] = "ML-DSA-65"
                    elif mutation == "key_id":
                        document["entries"][1]["key_id"] = document["entries"][0][
                            "key_id"
                        ]
                    elif mutation == "key_bytes":
                        document["entries"][1]["public_key_sha256"] = document[
                            "entries"
                        ][0]["public_key_sha256"]
                        (directory / "issuer-authorization.der").write_bytes(
                            b"configuration-public-key"
                        )
                    _write_registry(directory, document=document)
                    if mutation == "key_bytes":
                        (directory / "issuer-authorization.der").write_bytes(
                            b"configuration-public-key"
                        )
                    with self.assertRaises(TrustRegistryError):
                        PinnedTrustRegistry.load(directory)

    def test_rejects_symlink_and_writable_key_file(self) -> None:
        for mutation in ("symlink", "writable"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as raw_directory:
                    directory = Path(raw_directory)
                    _write_registry(directory)
                    public_key = directory / "configuration.der"
                    if mutation == "symlink":
                        target = directory / "target.der"
                        target.write_bytes(public_key.read_bytes())
                        public_key.unlink()
                        public_key.symlink_to(target.name)
                    else:
                        public_key.chmod(0o666)
                    with self.assertRaises(TrustRegistryError):
                        PinnedTrustRegistry.load(directory)

    def test_rejects_relative_or_writable_directory(self) -> None:
        with self.assertRaisesRegex(TrustRegistryError, "must be absolute"):
            PinnedTrustRegistry.load(Path("relative"))
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            _write_registry(directory)
            directory.chmod(0o777)
            try:
                with self.assertRaisesRegex(TrustRegistryError, "directory"):
                    PinnedTrustRegistry.load(directory)
            finally:
                directory.chmod(0o700)

    def test_rejects_registry_file_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            _write_registry(directory)
            registry_path = directory / TRUST_REGISTRY_FILENAME
            target = directory / "manifest-target.json"
            registry_path.rename(target)
            registry_path.symlink_to(target.name)
            with self.assertRaises(TrustRegistryError):
                PinnedTrustRegistry.load(directory)


if __name__ == "__main__":
    unittest.main()
