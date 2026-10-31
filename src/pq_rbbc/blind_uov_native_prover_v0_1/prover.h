/* Research-only ABI v1. uint16_t lengths are element counts, never bytes.
 * Live context and disjoint correctly sized buffers are C preconditions.
 * No borrowed pointers, global cache, protocol randomness or nonce search.
 */
#ifndef PQSAT_NATIVE_PROVER_V1_H
#define PQSAT_NATIVE_PROVER_V1_H
#include "relation.h"
uint32_t pqsat_prover_abi_version_v1(void);
const char *pqsat_prover_profile_v1(void);
int pqsat_prover_q_batch_v1(
    const pqsat_cap_context *ctx, const uint8_t *binding, size_t binding_n,
    const uint8_t *fields, size_t fields_n,
    const uint16_t *plain, size_t plain_n,
    const uint16_t *mask, size_t mask_n,
    const uint16_t *mplain, size_t mplain_n,
    const uint16_t *mmask, size_t mmask_n,
    const uint16_t *gammas, size_t gammas_n,
    uint16_t *q, size_t q_n, uint16_t *qbar, size_t qbar_n);
#endif
