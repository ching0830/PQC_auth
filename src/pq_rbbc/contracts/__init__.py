"""Canonical cross-module contracts for the PQ-RBBC system profile."""

from .system import (
    CONFIG_MAGIC,
    CONTEXT_BYTES,
    KEY_ID_BYTES,
    PUBLIC_KEY_DIGEST_BYTES,
    SYSTEM_BUNDLE_MAGIC,
    ContractError,
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)

__all__ = [
    "CONFIG_MAGIC",
    "CONTEXT_BYTES",
    "KEY_ID_BYTES",
    "PUBLIC_KEY_DIGEST_BYTES",
    "SYSTEM_BUNDLE_MAGIC",
    "ContractError",
    "KeyReference",
    "KeyRole",
    "SystemConfiguration",
    "SystemInitializationBundle",
    "ThresholdPolicy",
]
