"""Production-shaped S2 service boundary over the existing governance APIs."""

from __future__ import annotations

from pq_rbbc.contracts.system import (
    KEY_ROLE_ORDER,
    ContractError,
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.issuer_authorization import (
    AuthenticatedIssuerGrant,
    IssuerAuthorizationDecision,
    IssuerGrant,
    IssuerQuotaStore,
    authorize_issuance,
    issuer_grant_authentication_message,
)
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
    InitializationVerification,
    verify_initialization,
)

from .openssl_mldsa import (
    OpenSSLMLDSA65NonThresholdSigner,
    PinnedOpenSSLMLDSA65,
    RegistryBackedMLDSA65Verifier,
)
from .trust_registry import PinnedTrustRegistry, TrustRegistryError


def assemble_initialization_bundle(
    *,
    registry: PinnedTrustRegistry,
    configuration: SystemConfiguration,
    common_parameters_digest: bytes,
    federation_policy: ThresholdPolicy,
    opening_policy: ThresholdPolicy,
    opening_authorization_key: KeyReference,
    issuer_verification_key: KeyReference,
    opening_encryption_key: KeyReference,
) -> SystemInitializationBundle:
    """Assemble public references only; never generate or retain secret keys."""

    supplied = (
        opening_authorization_key,
        issuer_verification_key,
        opening_encryption_key,
    )
    expected_roles = (
        KeyRole.OPENING_AUTHORIZATION,
        KeyRole.ISSUER_VERIFICATION,
        KeyRole.OPENING_ENCRYPTION,
    )
    if tuple(reference.role for reference in supplied) != expected_roles:
        raise ContractError("external key references have wrong roles or order")
    keys = (
        registry.trusted_key(KeyRole.FEDERATION_CONFIGURATION).reference,
        registry.trusted_key(KeyRole.ISSUER_AUTHORIZATION).reference,
    ) + supplied
    if tuple(reference.role for reference in keys) != KEY_ROLE_ORDER:
        raise ContractError("assembled key roles are non-canonical")
    bundle = SystemInitializationBundle(
        configuration=configuration,
        common_parameters_digest=common_parameters_digest,
        federation_policy=federation_policy,
        opening_policy=opening_policy,
        keys=keys,
    )
    bundle.validate()
    return bundle


def publish_initialization(
    bundle: SystemInitializationBundle,
    signer: OpenSSLMLDSA65NonThresholdSigner,
) -> AuthenticatedSystemInitialization:
    """Sign the complete, existing initialization authentication domain."""

    key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    if signer.key_reference != key:
        raise ContractError("configuration signer does not match bundle key")
    message = INITIALIZATION_AUTH_DOMAIN + bundle.encode()
    return AuthenticatedSystemInitialization(
        bundle=bundle,
        authentication=signer.sign(message),
    )


def publish_issuer_grant(
    grant: IssuerGrant,
    signer: OpenSSLMLDSA65NonThresholdSigner,
) -> AuthenticatedIssuerGrant:
    """Sign the complete, role-bound existing issuer-grant domain."""

    if signer.key_reference.role is not KeyRole.ISSUER_AUTHORIZATION:
        raise ContractError("issuer grant signer has wrong role")
    if grant.issuer_authorization_key_id != signer.key_reference.key_id:
        raise ContractError("issuer grant signer key ID mismatch")
    signing_role = KeyRole.ISSUER_AUTHORIZATION
    message = issuer_grant_authentication_message(grant, signing_role)
    return AuthenticatedIssuerGrant(
        grant=grant,
        signing_role=signing_role,
        authentication=signer.sign(message),
    )


class PinnedSystemGovernanceService:
    """Request-facing verifier with trust fixed before requests are handled.

    Its request methods intentionally have no trust-anchor, verifier, public-key
    byte, or ``verified`` parameter.  The older low-level functions remain
    available for research dependency injection, but are not this boundary.
    """

    def __init__(
        self, registry: PinnedTrustRegistry, backend: PinnedOpenSSLMLDSA65
    ) -> None:
        self._registry = registry
        self._verifier = RegistryBackedMLDSA65Verifier(registry, backend)
        self._configuration_key = registry.trusted_key(
            KeyRole.FEDERATION_CONFIGURATION
        ).reference

    def verify_initialization(self, encoded: bytes) -> InitializationVerification:
        result = verify_initialization(
            encoded,
            self._configuration_key,
            self._verifier,
        )
        if not result.accepted or result.bundle is None:
            return result
        try:
            self._registry.resolve(
                result.bundle.key_for(KeyRole.ISSUER_AUTHORIZATION)
            )
        except (ContractError, TrustRegistryError) as error:
            return InitializationVerification(
                False,
                (f"issuer_authorization_trust:{type(error).__name__}",),
                None,
            )
        return result

    def authorize_issuance(
        self,
        authenticated_initialization: bytes,
        authenticated_grant: bytes,
        *,
        quota_store: IssuerQuotaStore,
        issuer_sid: bytes,
        now: int,
    ) -> IssuerAuthorizationDecision:
        return authorize_issuance(
            authenticated_initialization,
            authenticated_grant,
            trusted_configuration_key=self._configuration_key,
            initialization_verifier=self._verifier,
            grant_verifier=self._verifier,
            quota_store=quota_store,
            issuer_sid=issuer_sid,
            now=now,
        )
