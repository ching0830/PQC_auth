"""Explicit research-only CAP verifier; non-constant-time and unqualified.

Python remains the canonical default oracle. This module adds no library/profile
IO, compilation, discovery or statement allocation on import. The unchanged
package initializer reads its canonical profile.
Successful library images live until process exit for OpenMP safety. Factory
close prevents new binds; bound contexts own independent lifetimes.
"""
from __future__ import annotations

import hmac
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .relation import CAPStatement
    from .codec import CR, CZ, Pi2


class NativeVerifierError(RuntimeError):
    """Backend, binding or lifetime failure; never an ordinary invalid proof."""


def _backend(call, *args, **kwargs):
    from .native_relation import NativeRelationError
    from .native_opening import NativeOpeningError
    try:
        return call(*args, **kwargs)
    except (NativeRelationError, NativeOpeningError) as error:
        raise NativeVerifierError(str(error)) from error


def _output(value, expected_type):
    if type(value) is not expected_type:
        raise NativeVerifierError('malformed native output type')
    try:
        _backend(value.__post_init__)
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeVerifierError('malformed native output') from error
    return value


class NativeCAPVerifier:
    def __init__(self):
        raise NativeVerifierError('use NativeCAPVerifier.load')

    @classmethod
    def load(cls, *, relation_library_path: Path, relation_library_sha256: str,
             opening_library_path: Path, opening_library_sha256: str):
        from .native_relation import NativeRelationKernel, _configure_q
        from .native_opening import NativeOpeningKernel
        result = object.__new__(cls)
        result._relation = _backend(NativeRelationKernel.load, relation_library_path,
                                    expected_sha256=relation_library_sha256)
        _backend(_configure_q, result._relation._lib)
        result._opening = _backend(NativeOpeningKernel.load, opening_library_path,
                                   expected_sha256=opening_library_sha256)
        result._lock = threading.RLock()
        result._closed = False
        return result

    def bind(self, statement: CAPStatement, *, relation_threads: int, opening_threads: int):
        from .relation import CAPStatement
        from .uov import UOVPublicMap
        with self._lock:
            if self._closed:
                raise NativeVerifierError('use after close')
            # Copy validated immutable bytes; caller object mutation cannot change
            # the transcript half of a statement copied into the C context.
            try:
                if type(statement) is not CAPStatement or type(statement.public_map) is not UOVPublicMap:
                    raise NativeVerifierError('expected exact CAPStatement and UOVPublicMap')
                public = object.__new__(UOVPublicMap)
                for name in ('canonical_cpk', 'public_map_digest', 'dense_coefficients'):
                    object.__setattr__(public, name, getattr(statement.public_map, name))
                snapshot = CAPStatement(public, statement.ctx, statement.u)
            except (AttributeError, TypeError, ValueError) as error:
                raise NativeVerifierError('invalid statement binding') from error
            relation = _backend(self._relation.bind, snapshot, threads=relation_threads)
            try:
                opening = _backend(self._opening.bind, threads=opening_threads)
                return BoundNativeCAPVerifier._create(snapshot, relation, opening)
            except BaseException:
                _backend(relation.close)
                raise

    def close(self):
        with self._lock:
            _backend(self._relation.close)
            _backend(self._opening.close)
            self._closed = True

    def __enter__(self):
        with self._lock:
            if self._closed:
                raise NativeVerifierError('use after close')
            return self

    def __exit__(self, *args):
        self.close()


class BoundNativeCAPVerifier:
    def __init__(self):
        raise NativeVerifierError('use NativeCAPVerifier.bind')

    @classmethod
    def _create(cls, statement, relation, opening):
        result = object.__new__(cls)
        result._statement, result._relation, result._opening = statement, relation, opening
        result._binding = relation.statement_binding_sha256
        result._snapshot = (statement.public_map.canonical_cpk,
                            statement.public_map.public_map_digest,
                            statement.public_map.dense_coefficients, statement.ctx, statement.u)
        result._lock = threading.RLock()
        result._closed = False
        return result

    def _live(self):
        if self._closed:
            raise NativeVerifierError('use after close')
        s = self._statement
        try:
            current = (s.public_map.canonical_cpk, s.public_map.public_map_digest,
                       s.public_map.dense_coefficients, s.ctx, s.u)
        except AttributeError as error:
            raise NativeVerifierError('statement binding mismatch') from error
        if (any(type(v) is not bytes for v in current) or current != self._snapshot
                or self._relation.statement_binding_sha256 != self._binding):
            raise NativeVerifierError('statement binding mismatch')

    def verify(self, c_r_bytes: bytes, c_z_bytes: bytes, pi_2_bytes: bytes) -> bool:
        return self._run(c_r_bytes, c_z_bytes, pi_2_bytes, wire=True)

    def verify_parsed(self, c_r: CR, c_z: CZ, pi_2: Pi2) -> bool:
        return self._run(c_r, c_z, pi_2, wire=False)

    def _run(self, cr, cz, pi, *, wire, phases=None, trace=None):
        from time import perf_counter_ns
        from .codec import decode_c_r, decode_c_z, decode_pi_2
        with self._lock:
            self._live()
            started = perf_counter_ns()
            try:
                if wire:
                    cr, cz, pi = decode_c_r(cr), decode_c_z(cz), decode_pi_2(pi)
                if phases is not None:
                    phases['decode'] = perf_counter_ns() - started
                return self._core(cr, cz, pi, nonce_checked=wire, phases=phases, trace=trace)
            except (TypeError, ValueError):
                # Only canonical proof validation errors reach this boundary.
                # Native errors are translated to RuntimeError separately.
                return False
            finally:
                if phases is not None:
                    phases['whole_verifier'] = perf_counter_ns() - started

    def _core(self, cr, cz, pi, *, nonce_checked, phases, trace):
        from time import perf_counter_ns
        from . import transcript as t
        from .verifier import _validate_parsed_inputs, _xor_base_field_delta
        from .tree import Opening, canonical_frontier_indices
        from .evaluation import evaluation_point
        from .native_relation import _FIELDS
        from .native_opening import NativeOpeningReplay, NativeConsistencyReplay
        from .relation import decode_correction_data
        from .response import decode_tcith_responses, encode_h3_q_and_qbar
        last = perf_counter_ns()
        def mark(name):
            nonlocal last
            now = perf_counter_ns()
            if phases is not None:
                phases[name] = now - last
            last = now
        try:
            s, cr, cz, pi = _validate_parsed_inputs(self._statement, cr, cz, pi)
            Opening(pi.opening.seeds)  # repeat nested exact-tuple validation
        except AttributeError:
            # A low-level forged parsed proof can omit dataclass slots.
            return False
        correction = decode_correction_data(cr.correction_data)
        mark('semantic_validation')
        # Strict wire decode already checked this received nonce exactly once.
        if not nonce_checked and not t.explicit_pow_passes(pi.h3, pi.pow_nonce):
            return False
        hidden = t.derive_hidden_positions(pi.h3, pi.pow_nonce)
        if not t.hidden_positions_are_admissible(hidden):
            return False
        frontier = canonical_frontier_indices(hidden)
        if len(frontier) != len(pi.opening.seeds):
            return False
        mark('nonce_frontier')
        replay = _backend(self._opening.reconstruct, salt=cr.salt, hidden_positions=hidden,
                          frontier_indices=frontier, frontier_seeds=pi.opening.seeds,
                          hidden_commitments=pi.hidden_leaf_commitments)
        _output(replay, NativeOpeningReplay)
        if replay.hidden_positions != hidden:
            raise NativeVerifierError('native opening challenge binding mismatch')
        mark('native_opening')
        deltas = cr.correction_data[32:]
        h1 = t.derive_h1(s.ctx, cr.salt, replay.commitment_transcript, deltas)
        points = t.derive_consistency_points(h1)
        mark('h1_points')
        consistency = _backend(self._opening.build_xi, replay, corrections=deltas,
                               alpha_prime=correction.alpha_prime,
                               consistency_points=points, field_ids=_FIELDS)
        _output(consistency, NativeConsistencyReplay)
        for offset in tuple(range(0, 832, 416)) + tuple(range(832, 6976, 384)):
            if consistency.xi_encoded[offset:offset+32] != correction.alpha_prime:
                raise NativeVerifierError('malformed native Xi constant')
        mark('native_consistency')
        expected_h2 = t.derive_h2_prime(h1, consistency.xi_encoded)
        if not hmac.compare_digest(expected_h2, cr.h2_prime):
            return False
        h2 = t.derive_h2(s.ctx, s.u, cr.h2_prime, cz.delta_z)
        qbar = decode_tcith_responses(pi.tcith_responses)
        gammas = (t.derive_gammas(h2, 0), t.derive_gammas(h2, 1))
        mark('h2_gammas')
        vectors = _backend(lambda: consistency.vectors)
        witness = tuple(_xor_base_field_delta(vp, bytes(72)+cz.delta_z, 'delta_z')
                        for vp, vm, vh in vectors)
        finite = tuple(evaluation_point(0 if r < 2 else 1, p) for r, p in enumerate(hidden))
        mark('input_conversion')
        constraints = _backend(self._relation.evaluate_batch, _FIELDS, witness)
        # Validate backend shape/range independently, including injected output.
        if type(constraints) is not tuple or len(constraints) != 18 or any(
            type(row) is not tuple or len(row) != 576 or any(
                type(v) is not int or not 0 <= v < (4096 if r < 2 else 2048) for v in row)
            for r, row in enumerate(constraints)):
            raise NativeVerifierError('malformed native constraints')
        mark('native_relation')
        q = _backend(self._relation.reconstruct_q_batch, _FIELDS, finite, constraints,
                     tuple(v[1] for v in vectors), qbar, gammas)
        from .response import _validate_groups
        try:
            _validate_groups(q, 'native q')
        except (TypeError, ValueError) as error:
            raise NativeVerifierError('malformed native q output') from error
        mark('q_reconstruction')
        packed = encode_h3_q_and_qbar(q, qbar)
        mark('q_qbar_encoding')
        expected_h3 = t.derive_h3(s.ctx, s.u, h2, packed)
        decision = hmac.compare_digest(expected_h3, pi.h3)
        mark('h3')
        if trace is not None:
            trace.update(commitments=replay.commitment_transcript, h1=h1, points=points,
                         corrected=vectors, xi=consistency.xi_encoded, h2_prime=expected_h2,
                         constraints=constraints, q=q, packed=packed, h3=expected_h3,
                         finite=finite, witness=witness, gammas=gammas, qbar=qbar)
        return decision

    def close(self):
        with self._lock:
            try:
                _backend(self._relation.close)
            finally:
                _backend(self._opening.close)
                self._closed = True

    def __enter__(self):
        with self._lock:
            self._live()
            return self

    def __exit__(self, *args):
        self.close()


__all__ = ('NativeVerifierError', 'NativeCAPVerifier', 'BoundNativeCAPVerifier')
