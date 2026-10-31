/* Research-only, non-constant-time until independently audited, unqualified.
 * Not a production provider. ABI v1 uses element counts, not byte counts,
 * for uint16_t buffers. No pointer is borrowed after create returns.
 * Callers must serialize free against use, pass live handles, and provide
 * actual buffers of the declared sizes (ordinary C pointer preconditions).
 */
#ifndef PQSAT_CAP_NATIVE_RELATION_V1_H
#define PQSAT_CAP_NATIVE_RELATION_V1_H
#include <stddef.h>
#include <stdint.h>

enum pqsat_cap_error {
    PQSAT_CAP_OK = 0,
    PQSAT_CAP_NULL = 1,
    PQSAT_CAP_LENGTH = 2,
    PQSAT_CAP_FIELD = 3,
    PQSAT_CAP_RANGE = 4,
    PQSAT_CAP_ALLOC = 5,
    PQSAT_CAP_STATE = 6,
    PQSAT_CAP_OVERFLOW = 7,
    PQSAT_CAP_IDENTITY = 8,
    PQSAT_CAP_THREADS = 9,
    PQSAT_CAP_INTERNAL = 10
};
typedef struct pqsat_cap_context pqsat_cap_context;

uint32_t pqsat_cap_abi_version(void);
uint32_t pqsat_cap_openmp_version(void);
int pqsat_cap_cpu_compatible(void);
uint32_t pqsat_cap_probe_threads(uint32_t threads);
int pqsat_cap_context_create(
    const uint8_t *dense, size_t dense_bytes,
    const uint8_t *u, size_t u_bytes,
    const uint8_t *map_digest, size_t map_digest_bytes,
    const uint8_t *binding, size_t binding_bytes,
    uint32_t threads, pqsat_cap_context **out);
int pqsat_cap_evaluate_batch(
    const pqsat_cap_context *ctx,
    const uint8_t *binding, size_t binding_bytes,
    const uint8_t *field_degrees, size_t repetitions,
    const uint16_t *witness, size_t witness_elements,
    uint16_t *out, size_t output_elements);
/* free(&null_handle) is an idempotent success; free(NULL) is NULL error. */
int pqsat_cap_context_free(pqsat_cap_context **ctx);
/* Additive q ABI v1; group/repetition/k order: 32 then 288 outputs.
 * fields=12,12,11*16; points=18 finite nonzero values; constraints=18*576;
 * masks/qbar=320; gammas=(16+18)*576 in group/k/j order. Disjoint buffers. */
uint32_t pqsat_cap_q_abi_version(void);
int pqsat_cap_reconstruct_q_batch_v1(
    const pqsat_cap_context *ctx, const uint8_t *binding, size_t binding_n,
    const uint8_t *fields, size_t fields_n,
    const uint16_t *points, size_t points_n,
    const uint16_t *constraints, size_t constraints_n,
    const uint16_t *masks, size_t masks_n,
    const uint16_t *qbar, size_t qbar_n,
    const uint16_t *gammas, size_t gammas_n,
    uint16_t *out, size_t out_n);
#endif
