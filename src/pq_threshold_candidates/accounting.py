"""Conditional byte estimates, never backend measurements.

Paper locations and derivations: docs/literature/threshold_backends/
HANDOFF_VERIFICATION_zh-TW.md. Unknown terms remain None through aggregation.
"""

from dataclasses import dataclass

from .contracts import Candidate, PROFILES, envelope_overhead, get_profile, uint


@dataclass(frozen=True)
class SizeEstimate:
    components: tuple[tuple[str, int | None], ...]

    def __post_init__(self) -> None:
        if type(self.components) is not tuple or not self.components:
            raise ValueError("nonempty immutable components required")
        names = set()
        for term in self.components:
            if type(term) is not tuple or len(term) != 2:
                raise ValueError("component must be a (name, bytes) tuple")
            name, value = term
            if type(name) is not str or not name or name in names:
                raise ValueError("unique nonempty component names required")
            names.add(name)
            if value is not None:
                uint(value, name)
        uint(self.known_bytes, "sum of known bytes")

    @property
    def known_bytes(self) -> int:
        return sum(value for _, value in self.components if value is not None)

    @property
    def unknown_terms(self) -> tuple[str, ...]:
        return tuple(name for name, value in self.components if value is None)

    @property
    def total_bytes(self) -> int | None:
        return None if self.unknown_terms else self.known_bytes

    def as_dict(self) -> dict:
        return {"evidence_kind": "estimated", "components": dict(self.components),
                "known_bytes": self.known_bytes, "unknown_terms": list(self.unknown_terms),
                "total_bytes": self.total_bytes}


def estimate_sizes(candidate: Candidate, profile_id: str, *,
                   sigma_bytes: int | None = 11644, extra_bytes: int | None = None,
                   g_bytes: int | None = None, delta_bytes: int | None = None) -> dict:
    profile = get_profile(candidate, profile_id)
    for name, value in (("sigma_bytes", sigma_bytes), ("extra_bytes", extra_bytes),
                        ("g_bytes", g_bytes), ("delta_bytes", delta_bytes)):
        if value is not None:
            uint(value, name)
    if candidate is not Candidate.GF and g_bytes is not None:
        raise ValueError("g_bytes applies only to TH-GF")
    if candidate is not Candidate.UT and delta_bytes is not None:
        raise ValueError("delta_bytes applies only to TH-UT")
    if candidate is Candidate.NIED:
        components = (("syndrome", 208), ("masked_plaintext", 48), ("tag", 32))
    elif candidate is Candidate.UT:
        components = (("ML_KEM_768_ciphertext", 1088), ("masked_plaintext", 48),
                      ("Delta_bytes", delta_bytes))
    else:
        # Two module vectors in c1; packed R_2^d encoding in c4.
        d, log_p = (4, 10) if profile_id == "gf-pompeii-d4-estimate-v1" else (9, 11)
        components = (("c1", 2 * 256 * d * log_p // 8), ("c2", 80 + 48),
                      ("c4", 256 * d // 8), ("g_bytes", g_bytes))
    ciphertext = SizeEstimate(components)
    ticket = SizeEstimate((("ctx_sn_h", 80),) + components
                          + (("sigma_bytes", sigma_bytes), ("extra_bytes", extra_bytes)))
    return {
        "candidate": candidate.value, "profile_id": profile.profile_id,
        "evidence_kind": "estimated", "sigma_status": "provisional_estimate",
        "ciphertext": ciphertext.as_dict(), "ticket": ticket.as_dict(),
        "research_envelope_overhead_bytes": envelope_overhead(candidate, profile_id),
        "extra_includes": "all framing, including the research envelope if used; not added automatically",
        "assumptions": "draft packed payload; no instantiated crypto or transport encoding",
    }


def comparison_report(*, sigma_bytes: int | None = 11644,
                      extra_bytes: int | None = None, g_bytes: int | None = None,
                      delta_bytes: int | None = None) -> dict:
    """Generated estimates cannot populate the observed section via this API."""
    rows = []
    for profile in PROFILES.values():
        rows.append({
            "candidate": profile.candidate.value, "profile_id": profile.profile_id,
            "implementation_stage": profile.implementation_stage,
            "security_assessment": profile.security_assessment,
            "threshold_execution": profile.threshold_execution,
            "opening_capability": profile.opening_capability,
            "setup_model": profile.setup_model,
            "open_parameters": list(profile.open_parameters),
            "production_qualified": False,
            "observed": {"evidence_kind": "observed", "ciphertext_bytes": None,
                         "ticket_bytes": None, "opening_rounds": None,
                         "opening_time_ns": None, "satellite_online_bytes": None},
            "estimated": estimate_sizes(
                profile.candidate, profile.profile_id, sigma_bytes=sigma_bytes,
                extra_bytes=extra_bytes,
                g_bytes=g_bytes if profile.candidate is Candidate.GF else None,
                delta_bytes=delta_bytes if profile.candidate is Candidate.UT else None),
            # Reports from a different protocol/profile must not become our measurements.
            "literature_reported": [],
        })
    return {"schema": "pq-threshold-candidate-comparison-v1", "profiles": rows}
