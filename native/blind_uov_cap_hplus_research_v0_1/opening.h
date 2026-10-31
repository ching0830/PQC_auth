/* Research only, non-constant-time, unqualified, not a production provider.
 * H+ ABI 2: all buffer lengths are BYTES. Buffers must be disjoint and actually
 * have the declared capacity. Serialize use/free of a live opaque context.
 * No caller pointers retained. Outputs unspecified on error; never consume.
 */
#ifndef PQSAT_OPENING_HPLUS_V1_H
#define PQSAT_OPENING_HPLUS_V1_H
#include <stdint.h>
#include <stddef.h>
typedef struct opening_context opening_context;
uint32_t opening_abi_version(void);
int opening_cpu_compatible(void);
const char *opening_backend(void);
const char *opening_headers(void);
uint32_t opening_openmp_version(void);
int opening_create(opening_context **out, double *table_seconds);
int opening_free(opening_context **ctx);
/* hidden: 18 u16le; indices: increasing u32le; seeds: 24 each;
 * commitments: 18*48; leaves: unified order 40960*24, hidden slots zero;
 * coverage: 40960 bytes of 0/1; transcript: repetition-major 40960*48;
 * eval: repetition-major P(2048),M(rho),Mhat(256), every element u16le.
 * Total eval size: 83584 bytes. timings: expansion, commitment, tape, eval.
 */
int opening_reconstruct(opening_context *ctx,
 const uint8_t *salt,size_t salt_n,const uint8_t *hidden,size_t hidden_n,
 const uint8_t *indices,size_t indices_n,const uint8_t *seeds,size_t seeds_n,
 const uint8_t *commitments,size_t commitments_n,uint32_t threads,
 uint8_t *leaves,size_t leaves_n,uint8_t *coverage,size_t coverage_n,
 uint8_t *transcript,size_t transcript_n,uint8_t *eval,size_t eval_n,
 double *timings,size_t timings_n);
/* corrections: 17*(256+32) bytes; fields: 12,12,11*16;
 * points: four u64le; corrected: same layout as eval; Xi: 6976 bytes.
 */
int opening_xi(opening_context *ctx,
 const uint8_t *hidden,size_t hidden_n,const uint8_t *fields,size_t fields_n,
 const uint8_t *eval,size_t eval_n,const uint8_t *corrections,size_t corrections_n,
 const uint8_t *alpha,size_t alpha_n,const uint8_t *points,size_t points_n,
 uint32_t threads,uint8_t *corrected,size_t corrected_n,
 uint8_t *xi,size_t xi_n,double *timings,size_t timings_n);
/* H+ ABI2 only; pointer to 32 immutable fingerprint bytes. */
const uint8_t *opening_profile_fingerprint(void);
#endif
