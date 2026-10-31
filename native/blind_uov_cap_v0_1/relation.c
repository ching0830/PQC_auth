/* See relation.h. No protocol parsing, proving or verification lives here. */
#include "relation.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

enum { REPS = 18, WITNESS = 2048, ROWS = 576, N = 184, M = 72,
       MONOMIALS = 17020, DENSE_BYTES = M * MONOMIALS };
_Static_assert(CHAR_BIT == 8 && sizeof(uint16_t) == 2, "8-bit bytes required");
_Static_assert(N * (N + 1) / 2 == MONOMIALS, "monomial coverage");

typedef struct { uint64_t lo, hi; } packed8;
typedef struct {
    uint16_t log[4096];
    uint16_t exp[8190];
} field_tables;

struct pqsat_cap_context {
    uint32_t magic;
    uint32_t threads;
    uint8_t map_digest[32];
    uint8_t binding[32];
    uint8_t u[M];
    field_tables f11, f12;
    uint8_t map[MONOMIALS][M]; /* monomial-major, equation-minor */
};
#define CONTEXT_MAGIC UINT32_C(0x50435131)

/* Compile-time test-only allocation fault injection. Not a runtime switch,
 * not enabled by either measurement build profile. */
#ifdef PQSAT_CAP_TEST_ALLOC_FAIL
static void *context_allocate(size_t bytes) { (void)bytes; return NULL; }
#else
static void *context_allocate(size_t bytes) { return calloc(1, bytes); }
#endif

uint32_t pqsat_cap_abi_version(void) { return 1; }
uint32_t pqsat_cap_openmp_version(void) { return _OPENMP; }

/* Baseline instructions even in the optional -march=native diagnostic.
 * Check every instruction extension enabled by GCC that can affect this C
 * kernel. GCC's CPU support check includes OS AVX state support. */
#if defined(__x86_64__) && defined(__GNUC__)
__attribute__((target("arch=x86-64")))
#endif
int pqsat_cap_cpu_compatible(void) {
#if defined(__x86_64__) && defined(__GNUC__)
    __builtin_cpu_init();
#define NEED(feature) do { if (!__builtin_cpu_supports(feature)) return 0; } while (0)
#ifdef __SSE2__
    NEED("sse2");
#endif
#ifdef __SSE3__
    NEED("sse3");
#endif
#ifdef __SSSE3__
    NEED("ssse3");
#endif
#ifdef __SSE4_1__
    NEED("sse4.1");
#endif
#ifdef __SSE4_2__
    NEED("sse4.2");
#endif
#ifdef __AVX__
    NEED("avx");
#endif
#ifdef __AVX2__
    NEED("avx2");
#endif
#ifdef __AVX512F__
    NEED("avx512f");
#endif
#ifdef __AVX512BW__
    NEED("avx512bw");
#endif
#ifdef __AVX512VL__
    NEED("avx512vl");
#endif
#ifdef __AVX512DQ__
    NEED("avx512dq");
#endif
#ifdef __AVX512CD__
    NEED("avx512cd");
#endif
#ifdef __AVX512VNNI__
    NEED("avx512vnni");
#endif
#ifdef __AVX512VBMI__
    NEED("avx512vbmi");
#endif
#ifdef __AVX512VBMI2__
    NEED("avx512vbmi2");
#endif
#ifdef __AVX512VPOPCNTDQ__
    NEED("avx512vpopcntdq");
#endif
#ifdef __AVX512BITALG__
    NEED("avx512bitalg");
#endif
#ifdef __BMI__
    NEED("bmi");
#endif
#ifdef __BMI2__
    NEED("bmi2");
#endif
#ifdef __LZCNT__
    NEED("lzcnt");
#endif
#ifdef __POPCNT__
    NEED("popcnt");
#endif
#ifdef __FMA__
    NEED("fma");
#endif
#ifdef __F16C__
    NEED("f16c");
#endif
#ifdef __GFNI__
    NEED("gfni");
#endif
#ifdef __PCLMUL__
    NEED("pclmul");
#endif
#ifdef __VPCLMULQDQ__
    NEED("vpclmulqdq");
#endif
#undef NEED
#endif
    return 1;
}

uint32_t pqsat_cap_probe_threads(uint32_t threads) {
    uint32_t actual = 0;
    if (threads < 1 || threads > REPS) return 0;
    #pragma omp parallel num_threads(threads)
    {
        #pragma omp single
        actual = (uint32_t)omp_get_num_threads();
    }
    return actual;
}

static uint16_t raw_mul(uint16_t a, uint16_t b, unsigned degree,
                        uint16_t polynomial) {
    uint16_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        b >>= 1;
        a = (uint16_t)(a << 1);
        if (a & (1u << degree)) a ^= polynomial;
    }
    return result;
}

static int make_field(field_tables *f, unsigned degree, uint16_t polynomial,
                      uint16_t generator) {
    unsigned order = (1u << degree) - 1;
    uint16_t value = 1;
    /* A full-cycle check makes generator choice an executable invariant. */
    memset(f->log, 0xff, sizeof(f->log));
    for (unsigned i = 0; i < order; ++i) {
        if (!value || value > order || f->log[value] != UINT16_MAX)
            return PQSAT_CAP_INTERNAL;
        f->log[value] = (uint16_t)i;
        f->exp[i] = value;
        f->exp[i + order] = value;
        value = raw_mul(value, generator, degree, polynomial);
    }
    return value == 1 ? PQSAT_CAP_OK : PQSAT_CAP_INTERNAL;
}

int pqsat_cap_context_create(
    const uint8_t *dense, size_t dense_bytes, const uint8_t *u, size_t u_bytes,
    const uint8_t *map_digest, size_t map_digest_bytes,
    const uint8_t *binding, size_t binding_bytes,
    uint32_t threads, pqsat_cap_context **out) {
    if (!out) return PQSAT_CAP_NULL;
    if (*out) return PQSAT_CAP_STATE; /* never overwrite/leak a live handle */
    if (!dense || !u || !map_digest || !binding) return PQSAT_CAP_NULL;
    if (dense_bytes != DENSE_BYTES || u_bytes != M || map_digest_bytes != 32
        || binding_bytes != 32) return PQSAT_CAP_LENGTH;
    if (threads < 1 || threads > REPS) return PQSAT_CAP_THREADS;
    pqsat_cap_context *ctx = context_allocate(sizeof(*ctx));
    if (!ctx) return PQSAT_CAP_ALLOC;
    int status = make_field(&ctx->f11, 11, 0x805, 2);
    if (!status) status = make_field(&ctx->f12, 12, 0x1009, 3);
    if (status) { free(ctx); return status; }
    for (size_t monomial = 0; monomial < MONOMIALS; ++monomial)
        for (size_t equation = 0; equation < M; ++equation)
            ctx->map[monomial][equation] = dense[equation * MONOMIALS + monomial];
    memcpy(ctx->map_digest, map_digest, 32);
    memcpy(ctx->binding, binding, 32);
    memcpy(ctx->u, u, M);
    ctx->threads = threads;
    ctx->magic = CONTEXT_MAGIC;
    *out = ctx;
    return PQSAT_CAP_OK;
}

static packed8 pack(const uint16_t p[8]) {
    packed8 result = {0, 0};
    for (unsigned i = 0; i < 4; ++i) {
        result.lo |= (uint64_t)p[i] << (16 * i);
        result.hi |= (uint64_t)p[i + 4] << (16 * i);
    }
    return result;
}

static packed8 xor8(packed8 a, packed8 b) {
    packed8 result = {a.lo ^ b.lo, a.hi ^ b.hi};
    return result;
}

static packed8 xtime8(packed8 p) {
    /* Multiplication by the GF(256) indeterminate, over K coefficients:
     * x^8 = x^4+x^3+x+1. No integer carry and no field truncation. */
    uint64_t top = p.hi >> 48;
    packed8 result = {
        (p.lo << 16) ^ top ^ (top << 16) ^ (top << 48),
        (p.hi << 16) ^ (p.lo >> 48) ^ top
    };
    return result;
}

static void nibble_tables(const uint16_t product[8], packed8 low[16],
                           packed8 high[16]) {
    low[0] = (packed8){0, 0};
    high[0] = (packed8){0, 0};
    packed8 basis = pack(product);
    for (unsigned bit = 0; bit < 8; ++bit) {
        packed8 *table = bit < 4 ? low : high;
        unsigned limit = 1u << (bit % 4);
        for (unsigned i = 0; i < limit; ++i)
            table[i + limit] = xor8(table[i], basis);
        basis = xtime8(basis);
    }
}

static void evaluate_one(const pqsat_cap_context *ctx, const field_tables *f,
                         const uint16_t *w, uint16_t *out) {
    packed8 accum[M];
    uint16_t logs[N][8];
    for (unsigned i = 0; i < N; ++i)
        for (unsigned b = 0; b < 8; ++b)
            logs[i][b] = f->log[w[ROWS + 8 * i + b]];
    for (unsigned e = 0; e < M; ++e) {
        uint16_t initial[8];
        for (unsigned b = 0; b < 8; ++b)
            initial[b] = w[e * 8 + b] ^ ((ctx->u[e] >> b) & 1);
        accum[e] = pack(initial);
    }
    unsigned monomial = 0;
    for (unsigned first = 0; first < N; ++first) {
        for (unsigned second = first; second < N; ++second, ++monomial) {
            uint16_t product[15] = {0};
            for (unsigned a = 0; a < 8; ++a) {
                if (logs[first][a] == UINT16_MAX) continue;
                for (unsigned b = 0; b < 8; ++b) {
                    if (logs[second][b] != UINT16_MAX)
                        product[a + b] ^= f->exp[logs[first][a] + logs[second][b]];
                }
            }
            for (int power = 14; power >= 8; --power) {
                uint16_t value = product[power];
                product[power - 4] ^= value;
                product[power - 5] ^= value;
                product[power - 7] ^= value;
                product[power - 8] ^= value;
            }
            packed8 low[16], high[16];
            nibble_tables(product, low, high);
            for (unsigned e = 0; e < M; ++e) {
                uint8_t coefficient = ctx->map[monomial][e];
                accum[e] = xor8(accum[e], xor8(low[coefficient & 15],
                                              high[coefficient >> 4]));
            }
        }
    }
    for (unsigned e = 0; e < M; ++e)
        for (unsigned b = 0; b < 4; ++b) {
            out[e * 8 + b] = (uint16_t)(accum[e].lo >> (16 * b));
            out[e * 8 + b + 4] = (uint16_t)(accum[e].hi >> (16 * b));
        }
}

int pqsat_cap_evaluate_batch(
    const pqsat_cap_context *ctx, const uint8_t *binding, size_t binding_bytes,
    const uint8_t *field_degrees, size_t repetitions,
    const uint16_t *witness, size_t witness_elements,
    uint16_t *out, size_t output_elements) {
    if (!ctx || !binding || !field_degrees || !witness || !out)
        return PQSAT_CAP_NULL;
    if (ctx->magic != CONTEXT_MAGIC) return PQSAT_CAP_STATE;
    if (repetitions > SIZE_MAX / WITNESS || repetitions > SIZE_MAX / ROWS
        || witness_elements > SIZE_MAX / sizeof(uint16_t)
        || output_elements > SIZE_MAX / sizeof(uint16_t)) return PQSAT_CAP_OVERFLOW;
    if (binding_bytes != 32 || repetitions != REPS
        || witness_elements != REPS * WITNESS
        || output_elements != REPS * ROWS) return PQSAT_CAP_LENGTH;
    if (memcmp(binding, ctx->binding, 32)) return PQSAT_CAP_IDENTITY;
    /* Validate the entire batch before writing any output. */
    for (size_t r = 0; r < REPS; ++r) {
        unsigned degree = r < 2 ? 12 : 11;
        if (field_degrees[r] != degree) return PQSAT_CAP_FIELD;
        for (size_t j = 0; j < WITNESS; ++j)
            if (witness[r * WITNESS + j] >= (1u << degree)) return PQSAT_CAP_RANGE;
    }
    /* Per-call storage; context is read-only. No omp_set_num_threads/global
     * configuration. The caller controls affinity before creating its team. */
    #pragma omp parallel for schedule(static) num_threads(ctx->threads)
    for (int r = 0; r < REPS; ++r)
        evaluate_one(ctx, r < 2 ? &ctx->f12 : &ctx->f11,
                     witness + r * WITNESS, out + r * ROWS);
    return PQSAT_CAP_OK;
}

int pqsat_cap_context_free(pqsat_cap_context **ctx) {
    if (!ctx) return PQSAT_CAP_NULL;
    if (!*ctx) return PQSAT_CAP_OK;
    if ((*ctx)->magic != CONTEXT_MAGIC) return PQSAT_CAP_STATE;
    (*ctx)->magic = 0;
    free(*ctx);
    *ctx = NULL;
    return PQSAT_CAP_OK;
}

/* Additive Protocol-11 ABI, independent of the unchanged evaluate ABI v1.
 * All uint16_t lengths are element counts. Validate the complete batch before
 * output writes; use copied context field tables and binding. */
uint32_t pqsat_cap_q_abi_version(void) { return 1; }
static uint16_t table_mul(const field_tables *f, uint16_t a, uint16_t b) {
    return a && b ? f->exp[f->log[a] + f->log[b]] : 0;
}
int pqsat_cap_reconstruct_q_batch_v1(
    const pqsat_cap_context *ctx, const uint8_t *binding, size_t binding_n,
    const uint8_t *fields, size_t fields_n,
    const uint16_t *points, size_t points_n,
    const uint16_t *constraints, size_t constraints_n,
    const uint16_t *masks, size_t masks_n,
    const uint16_t *qbar, size_t qbar_n,
    const uint16_t *gammas, size_t gammas_n,
    uint16_t *out, size_t out_n) {
    if (!ctx || !binding || !fields || !points || !constraints || !masks ||
        !qbar || !gammas || !out) return PQSAT_CAP_NULL;
    if (ctx->magic != CONTEXT_MAGIC) return PQSAT_CAP_STATE;
    if (binding_n != 32 || fields_n != 18 || points_n != 18 ||
        constraints_n != 18*576 || masks_n != 320 || qbar_n != 320 ||
        gammas_n != 34*576 || out_n != 320) return PQSAT_CAP_LENGTH;
    if (memcmp(binding, ctx->binding, 32)) return PQSAT_CAP_IDENTITY;
    for (unsigned r=0; r<18; ++r) {
        unsigned d=r<2?12:11, bound=1u<<d, rho=r<2?16:18;
        unsigned offset=r<2?r*16:32+(r-2)*18;
        if (fields[r] != d) return PQSAT_CAP_FIELD;
        if (!points[r] || points[r]>=bound) return PQSAT_CAP_RANGE;
        for (unsigned j=0; j<576; ++j)
            if (constraints[r*576+j]>=bound) return PQSAT_CAP_RANGE;
        for (unsigned k=0; k<rho; ++k)
            if (masks[offset+k]>=bound || qbar[offset+k]>=bound) return PQSAT_CAP_RANGE;
    }
    for (unsigned j=0; j<34*576; ++j)
        if (gammas[j]>=(j<16*576?4096:2048)) return PQSAT_CAP_RANGE;
    #pragma omp parallel for schedule(static) num_threads(ctx->threads)
    for (int r=0; r<18; ++r) {
        const field_tables *f=r<2?&ctx->f12:&ctx->f11;
        unsigned rho=r<2?16:18, offset=r<2?r*16:32+(r-2)*18;
        unsigned goffset=r<2?0:16*576, order=r<2?4095:2047;
        uint16_t x=points[r], inverse=f->exp[order-f->log[x]];
        for (unsigned k=0; k<rho; ++k) {
            uint16_t right=table_mul(f,x,masks[offset+k]);
            for (unsigned j=0; j<576; ++j)
                right ^= table_mul(f,gammas[goffset+k*576+j],constraints[r*576+j]);
            out[offset+k]=table_mul(f,inverse,right)^table_mul(f,x,qbar[offset+k]);
        }
    }
    return PQSAT_CAP_OK;
}
