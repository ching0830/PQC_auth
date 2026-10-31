/* Bounded extension of the unchanged full-profile relation evaluator.
 * Every repetition is evaluated at 0, 1, 2, including the constant check.
 * Scalar interpolation is exactly c+lX+qX^2, with modulus 0x1009 / 0x805.
 * This kernel is non-constant-time and unqualified, like its research oracle.
 */
#include "prover.h"
#include <stdlib.h>
#include <string.h>

enum { REPS=18, W=2048, ROWS=576, RESP=320, GAMMAS=34*576 };
uint32_t pqsat_prover_abi_version_v1(void) { return 1; }
const char *pqsat_prover_profile_v1(void) {
    return "fc6706429f10d3bcc5600d4b427ca604a19f22c31ec35b171f40513b1a4bcb25";
}
static uint16_t mul(uint16_t a, uint16_t b, unsigned degree) {
    uint16_t out=0, polynomial=degree==12?0x1009:0x805;
    while (b) {
        if (b&1) out^=a;
        b>>=1;
        a=(uint16_t)(a<<1);
        if (a&(1u<<degree)) a^=polynomial;
    }
    return out;
}
static uint16_t inverse(uint16_t a, unsigned degree) {
    uint16_t out=1;
    unsigned exponent=(1u<<degree)-2;
    while (exponent) {
        if (exponent&1) out=mul(out,a,degree);
        a=mul(a,a,degree);
        exponent>>=1;
    }
    return out;
}
static void wipe(void *p, size_t n) {
    volatile unsigned char *v=p;
    while (n--) *v++=0;
}
int pqsat_prover_q_batch_v1(
    const pqsat_cap_context *ctx, const uint8_t *binding, size_t binding_n,
    const uint8_t *fields, size_t fields_n,
    const uint16_t *plain, size_t plain_n,
    const uint16_t *mask, size_t mask_n,
    const uint16_t *mplain, size_t mplain_n,
    const uint16_t *mmask, size_t mmask_n,
    const uint16_t *gammas, size_t gammas_n,
    uint16_t *q, size_t q_n, uint16_t *qbar, size_t qbar_n) {
    if (!ctx||!binding||!fields||!plain||!mask||!mplain||!mmask||!gammas||!q||!qbar)
        return PQSAT_CAP_NULL;
    if (binding_n!=32||fields_n!=REPS||plain_n!=REPS*W||mask_n!=REPS*W||
        mplain_n!=RESP||mmask_n!=RESP||gammas_n!=GAMMAS||q_n!=RESP||qbar_n!=RESP)
        return PQSAT_CAP_LENGTH;
    /* Validate all inputs before allocation or any output write. */
    for (unsigned r=0;r<REPS;r++) {
        unsigned degree=r<2?12:11, bound=1u<<degree, rho=r<2?16:18;
        unsigned off=r<2?r*16:32+(r-2)*18;
        if (fields[r]!=degree) return PQSAT_CAP_FIELD;
        for (unsigned j=0;j<W;j++)
            if (plain[r*W+j]>1||mask[r*W+j]>=bound) return PQSAT_CAP_RANGE;
        for (unsigned k=0;k<rho;k++)
            if (mplain[off+k]>=bound||mmask[off+k]>=bound) return PQSAT_CAP_RANGE;
    }
    for (unsigned j=0;j<GAMMAS;j++)
        if (gammas[j]>=(j<16*ROWS?4096:2048)) return PQSAT_CAP_RANGE;
    enum { WORK=REPS*W+3*REPS*ROWS };
#ifdef PQSAT_PROVER_TEST_ALLOC_FAIL
    uint16_t *work=NULL;
#else
    uint16_t *work=calloc(WORK,sizeof(*work));
#endif
    if (!work) return PQSAT_CAP_ALLOC;
    uint16_t *values=work, *at[3]={work+REPS*W,work+REPS*W+REPS*ROWS,
                                work+REPS*W+2*REPS*ROWS};
    int status=PQSAT_CAP_OK;
    for (unsigned point=0;point<3;point++) {
        for (unsigned r=0;r<REPS;r++)
            for (unsigned j=0;j<W;j++)
                values[r*W+j]=plain[r*W+j]^mul(mask[r*W+j],(uint16_t)point,r<2?12:11);
        status=pqsat_cap_evaluate_batch(ctx,binding,binding_n,fields,fields_n,
                                       values,REPS*W,at[point],REPS*ROWS);
        if (status) goto done;
    }
    /* Do not replace this with a single witness accept or skip repeated checks. */
    for (unsigned j=0;j<REPS*ROWS;j++)
        if (at[0][j]) { status=PQSAT_CAP_INTERNAL; goto done; }
    uint16_t result[2*RESP];
    for (unsigned r=0;r<REPS;r++) {
        unsigned degree=r<2?12:11, rho=r<2?16:18;
        unsigned off=r<2?r*16:32+(r-2)*18, goff=r<2?0:16*ROWS;
        uint16_t inv=inverse(mul(2,2,degree)^2,degree), linear[ROWS], quad[ROWS];
        for (unsigned j=0;j<ROWS;j++) {
            uint16_t c=at[0][r*ROWS+j], lq=at[1][r*ROWS+j]^c;
            quad[j]=mul(at[2][r*ROWS+j]^c^mul(2,lq,degree),inv,degree);
            linear[j]=lq^quad[j];
        }
        for (unsigned k=0;k<rho;k++) {
            uint16_t l=mplain[off+k], h=mmask[off+k];
            for (unsigned j=0;j<ROWS;j++) {
                uint16_t gamma=gammas[goff+k*ROWS+j];
                l^=mul(gamma,linear[j],degree);
                h^=mul(gamma,quad[j],degree);
            }
            result[off+k]=l;
            result[RESP+off+k]=h;
        }
        wipe(linear,sizeof(linear)); wipe(quad,sizeof(quad));
    }
    memcpy(q,result,RESP*sizeof(*q));
    memcpy(qbar,result+RESP,RESP*sizeof(*qbar));
    wipe(result,sizeof(result));
done:
    wipe(work,WORK*sizeof(*work));
    free(work);
    return status;
}
