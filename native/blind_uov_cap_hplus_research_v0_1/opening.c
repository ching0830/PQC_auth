#define _POSIX_C_SOURCE 200809L
#include "opening.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <omp.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
_Static_assert(CHAR_BIT == 8, "eight-bit bytes required");
enum { LEAVES=40960, BASE=40959, NODES=81919, EVAL=83584 };
/* Errors: null=1, length=2, range=3, shape=4, allocation=5, state=6,
 * backend=7, threads=8, invariant=9. */
struct opening_context { uint32_t magic; uint16_t reciprocal[2][4096]; EVP_MD *md; };
#define MAGIC 0x4f504e32u
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9; }
static uint16_t get16(const uint8_t *p) { return p[0]|((uint16_t)p[1]<<8); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p)|((uint32_t)get16(p+2)<<16); }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p)|((uint64_t)get32(p+4)<<32); }
static void put16(uint8_t *p,uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static uint16_t mul(uint16_t a,uint16_t b,unsigned d) {
 uint16_t z=0, poly=d==12?0x1009:0x805;
 while(b) { if(b&1) z^=a; b>>=1; a<<=1; if(a&(1u<<d)) a^=poly; } return z;
}
static uint16_t inv(uint16_t a,unsigned d) {
 uint16_t z=1; unsigned e=(1u<<d)-2;
 while(e) { if(e&1) z=mul(z,a,d); a=mul(a,a,d); e>>=1; } return z;
}
uint32_t opening_abi_version(void) { return 2; }
int opening_cpu_compatible(void) {
#if defined(__x86_64__) && defined(__GNUC__)
 __builtin_cpu_init(); return __builtin_cpu_supports("sse2")!=0;
#else
 return 0;
#endif
}
const char *opening_backend(void) { return OpenSSL_version(OPENSSL_VERSION); }
const char *opening_headers(void) { return OPENSSL_VERSION_TEXT; }
uint32_t opening_openmp_version(void) { return _OPENMP; }
int opening_create(opening_context **out,double *table_seconds) {
 if(!out||!table_seconds) return 1;
 if(*out) return 6;
 opening_context *c=calloc(1,sizeof(*c)); if(!c) return 5;
 c->md=EVP_MD_fetch(NULL,"SHAKE256","provider=default");
 if(!c->md) { free(c); return 7; }
 const OSSL_PROVIDER *provider=EVP_MD_get0_provider(c->md);
 if(!provider||strcmp(OSSL_PROVIDER_get0_name(provider),"default")) { EVP_MD_free(c->md); free(c); return 7; }
 double t=now();
 for(unsigned g=0;g<2;g++) { unsigned d=g?11:12, n=1u<<d;
  for(unsigned p=0;p<n-1;p++) c->reciprocal[g][p]=inv((uint16_t)(p+1),d);
  c->reciprocal[g][n-1]=0;
 }
 *table_seconds=now()-t; c->magic=MAGIC; *out=c; return 0;
}
int opening_free(opening_context **c) {
 if(!c) return 1;
 if(!*c) return 0;
 if((*c)->magic!=MAGIC) return 6;
 EVP_MD_free((*c)->md); OPENSSL_cleanse(*c,sizeof(**c)); free(*c); *c=NULL; return 0;
}
static size_t unified(unsigned r,unsigned p) { return p<2048?18*p+r:36864+2*(p-2048)+r; }
static size_t offset(unsigned r) { return r<2?r*4640:9280+(r-2)*4644; }
static size_t coffset(unsigned r) { return r<2?r*4096:8192+(r-2)*2048; }
static int hidden_ok(const uint8_t *h) {
 for(unsigned r=0;r<18;r++) if(get16(h+2*r)>=(r<2?4095:2047)) return 3;
 return 0;
}
static const uint8_t fp[32]={0x85,0x79,0x63,0x87,0x97,0xc2,0xfa,0x6f,0x9e,0xf0,0x9a,0xef,0x51,0x8e,0x81,0x21,0x3e,0x56,0x61,0x15,0xe0,0x42,0x74,0x4e,0x5b,0x78,0x2d,0x8c,0x49,0xc5,0xf0,0x7d};
const uint8_t *opening_profile_fingerprint(void) { return fp; }
static size_t field(uint8_t *out,size_t at,const uint8_t *v,size_t n) {
 out[at++]=0;out[at++]=0;out[at++]=(uint8_t)(n>>8);out[at++]=(uint8_t)n;
 memcpy(out+at,v,n); return at+n;
}
/* Fixed bounded canonical tuple, no per-leaf allocation or callback. */
static size_t input(uint8_t out[192],const char *domain,const uint8_t *salt,
 unsigned node,unsigned r,unsigned p,const uint8_t *seed,int leaf) {
 size_t n=strlen(domain), at=0; out[at++]=0;out[at++]=(uint8_t)n;
 memcpy(out+at,domain,n);at+=n;out[at++]=0;out[at++]=leaf?5:4;
 at=field(out,at,fp,32);at=field(out,at,salt,48);
 uint8_t v[4];
 if(leaf) { v[0]=(uint8_t)(r>>8);v[1]=(uint8_t)r;at=field(out,at,v,2);
  v[0]=(uint8_t)(p>>8);v[1]=(uint8_t)p;at=field(out,at,v,2);
 } else { v[0]=(uint8_t)(node>>24);v[1]=(uint8_t)(node>>16);v[2]=(uint8_t)(node>>8);v[3]=(uint8_t)node;at=field(out,at,v,4); }
 return field(out,at,seed,24);
}
static int xof(EVP_MD_CTX *x,const EVP_MD *md,const uint8_t *in,size_t n,uint8_t *out,size_t m) {
 return EVP_DigestInit_ex(x,md,NULL)==1&&EVP_DigestUpdate(x,in,n)==1&&EVP_DigestFinalXOF(x,out,m)==1?0:7;
}
static int expand(EVP_MD_CTX *x,const EVP_MD *md,unsigned node,const uint8_t *seed,
 const uint8_t *salt,uint8_t *leaves,uint8_t *coverage) {
 if(node>=BASE) { unsigned i=node-BASE; if(i>=LEAVES||coverage[i]) return 9;
  memcpy(leaves+24*i,seed,24);coverage[i]=1;return 0; }
 uint8_t in[192],children[48]; size_t n=input(in,"PQSAT-BUOV-CAP-HPLUS-0.1/SEED-DERIVE",salt,node,0,0,seed,0);
 int status=xof(x,md,in,n,children,48);
 if(!status) status=expand(x,md,2*node+1,children,salt,leaves,coverage);
 if(!status) status=expand(x,md,2*node+2,children+24,salt,leaves,coverage);
 OPENSSL_cleanse(children,sizeof(children));OPENSSL_cleanse(in,sizeof(in));return status;
}
int opening_reconstruct(opening_context *c,
 const uint8_t *salt,size_t sn,const uint8_t *h,size_t hn,
 const uint8_t *idx,size_t in,const uint8_t *seeds,size_t sen,
 const uint8_t *comm,size_t cn,uint32_t threads,
 uint8_t *leaves,size_t ln,uint8_t *coverage,size_t covn,
 uint8_t *trans,size_t tn,uint8_t *eval,size_t en,double *tim,size_t timn) {
 if(!c||!salt||!h||!idx||!seeds||!comm||!leaves||!coverage||!trans||!eval||!tim) return 1;
 if(c->magic!=MAGIC) return 6;
 if(sn!=48||hn!=36||in%4||in<13*4||in>174*4||sen!=in/4*24||cn!=864||ln!=LEAVES*24||covn!=LEAVES||tn!=LEAVES*48||en!=EVAL||timn!=4) return 2;
 if(threads<1||threads>18) return 8;
 int status=hidden_ok(h);if(status) return status;
 /* A node is canonical iff unblocked and its parent is blocked. This
  * independently derives the entire sorted maximal frontier before expansion. */
 uint8_t blocked[NODES]={0};blocked[0]=1;
 for(unsigned r=0;r<18;r++) { unsigned n=BASE+(unsigned)unified(r,get16(h+2*r));
  for(;;) { blocked[n]=1;if(!n) break;n=(n-1)/2; } }
 size_t count=0;
 for(unsigned n=1;n<NODES;n++) if(!blocked[n]&&blocked[(n-1)/2]) {
  if(count>=in/4||get32(idx+count*4)!=n) return 4;
  count++;
 }
 if(count!=in/4) return 4;
 uint8_t *tapes=calloc(LEAVES,296);if(!tapes) return 5;
 EVP_MD_CTX *xs[18]={0};
 for(unsigned i=0;i<threads;i++) { xs[i]=EVP_MD_CTX_new();if(!xs[i]) { status=5;goto done; } }
 memset(leaves,0,ln);memset(coverage,0,covn);memset(eval,0,en);
 double t=now();int failure=0;
 #pragma omp parallel for schedule(dynamic,1) num_threads(threads) reduction(|:failure)
 for(size_t i=0;i<count;i++) failure|=expand(xs[omp_get_thread_num()],c->md,get32(idx+4*i),seeds+24*i,salt,leaves,coverage);
 tim[0]=now()-t;if(failure) { status=failure;goto done; }
 for(unsigned i=0;i<LEAVES;i++) if(coverage[i]!=(uint8_t)!blocked[BASE+i]) { status=9;goto done; }
 t=now();
 #pragma omp parallel for schedule(dynamic,1) num_threads(threads) reduction(|:failure)
 for(unsigned r=0;r<18;r++) {
  unsigned n=r<2?4096:2048;uint8_t inbuf[192];EVP_MD_CTX *x=xs[omp_get_thread_num()];
  for(unsigned p=0;p<n;p++) { uint8_t *out=trans+(coffset(r)+p)*48;
   if(p==get16(h+2*r)) { memcpy(out,comm+r*48,48);continue; }
   size_t len=input(inbuf,"PQSAT-BUOV-CAP-HPLUS-0.1/LEAF-COMMIT",salt,0,r,p,leaves+unified(r,p)*24,1);
   failure|=xof(x,c->md,inbuf,len,out,48);
  } OPENSSL_cleanse(inbuf,sizeof(inbuf));
 }
 tim[1]=now()-t;if(failure) { status=failure;goto done; }
 t=now();
 #pragma omp parallel for schedule(dynamic,1) num_threads(threads) reduction(|:failure)
 for(unsigned r=0;r<18;r++) {
  unsigned n=r<2?4096:2048;EVP_MD_CTX *x=xs[omp_get_thread_num()];uint8_t inbuf[192];
  for(unsigned p=0;p<n;p++) { if(p==get16(h+2*r)) continue;
   size_t u=unified(r,p),len=input(inbuf,"PQSAT-BUOV-CAP-HPLUS-0.1/TAPE-EXPAND",salt,0,r,p,leaves+u*24,1);
   failure|=xof(x,c->md,inbuf,len,tapes+u*296,r<2?290:291);
   if(r>=2) tapes[u*296+290]&=3;
  } OPENSSL_cleanse(inbuf,sizeof(inbuf));
 }
 tim[2]=now()-t;if(failure) { status=failure;goto done; }
 t=now();
 #pragma omp parallel for schedule(dynamic,1) num_threads(threads)
 for(unsigned r=0;r<18;r++) {
  unsigned d=r<2?12:11,n=1u<<d,bits=r<2?2320:2322;uint64_t planes[12][37]={{0}};
  for(unsigned p=0;p<n;p++) { if(p==get16(h+2*r)) continue;
   uint16_t coeff=1^mul((uint16_t)(get16(h+2*r)+1),c->reciprocal[r<2?0:1][p],d);
   const uint8_t *tape=tapes+unified(r,p)*296;
   for(unsigned b=0;b<d;b++) if((coeff>>b)&1)
    for(unsigned w=0;w<37;w++) planes[b][w]^=get64(tape+w*8);
  }
  uint8_t *out=eval+offset(r);
  for(unsigned j=0;j<bits;j++) { uint16_t v=0;
   for(unsigned b=0;b<d;b++) v|=((planes[b][j/64]>>(j%64))&1)<<b;
   put16(out+2*j,v);
  }
 }
 tim[3]=now()-t;
done:
 for(unsigned i=0;i<threads;i++) EVP_MD_CTX_free(xs[i]);
 OPENSSL_cleanse(tapes,LEAVES*296);free(tapes);return status;
}
static uint64_t mul64(uint64_t a,uint64_t b) {
 uint64_t z=0;for(unsigned i=0;i<64;i++) { if(b&1) z^=a;b>>=1;uint64_t top=a>>63;a<<=1;if(top) a^=0x1b; } return z;
}
int opening_xi(opening_context *c,
 const uint8_t *h,size_t hn,const uint8_t *fields,size_t fn,
 const uint8_t *eval,size_t en,const uint8_t *delta,size_t dn,
 const uint8_t *alpha,size_t an,const uint8_t *points,size_t pn,
 uint32_t threads,uint8_t *corrected,size_t con,uint8_t *xi,size_t xn,double *tim,size_t timn) {
 if(!c||!h||!fields||!eval||!delta||!alpha||!points||!corrected||!xi||!tim) return 1;
 if(c->magic!=MAGIC) return 6;
 if(hn!=36||fn!=18||en!=EVAL||dn!=4896||an!=32||pn!=32||con!=EVAL||xn!=6976||timn!=2) return 2;
 if(threads<1||threads>18) return 8;
 int status=hidden_ok(h);if(status) return status;
 for(unsigned r=0;r<18;r++) { unsigned d=r<2?12:11,bits=r<2?2320:2322;
  if(fields[r]!=d) return 4;
  for(unsigned j=0;j<bits;j++) if(get16(eval+offset(r)+2*j)>=(1u<<d)) return 3;
 }
 double t=now();memcpy(corrected,eval,EVAL);memset(xi,0,xn);
 for(unsigned r=1;r<18;r++) { uint8_t *v=corrected+offset(r);unsigned rho=r<2?16:18;
  const uint8_t *dr=delta+(r-1)*288;
  for(unsigned j=0;j<2048;j++) v[2*j]^=(dr[j/8]>>(j%8))&1;
  for(unsigned j=0;j<256;j++) v[2*(2048+rho+j)]^=(dr[256+j/8]>>(j%8))&1;
 }
 tim[0]=now()-t;t=now();
 #pragma omp parallel for schedule(static) num_threads(threads)
 for(unsigned r=0;r<18;r++) {
  unsigned d=r<2?12:11,rho=r<2?16:18;const uint8_t *v=corrected+offset(r);
  uint16_t lifted[256];for(unsigned j=0;j<256;j++) lifted[j]=get16(v+2*(2048+rho+j));
  for(unsigned b=0;b<d;b++) {
   uint64_t coeff[32]={0};
   for(unsigned j=0;j<2048;j++) coeff[j/64]|=(uint64_t)((get16(v+2*j)>>b)&1)<<(j%64);
   for(unsigned k=0;k<4;k++) { uint64_t z=0,point=get64(points+8*k);
    for(int j=31;j>=0;j--) z=mul64(z,point)^coeff[j];
    z=mul64(z,point); /* H+: Mhat remains unscaled. */
    for(unsigned j=0;j<64;j++) lifted[k*64+j]^=((z>>j)&1)<<b;
   }
  }
  size_t at=r<2?r*416:832+(r-2)*384;memcpy(xi+at,alpha,32);at+=32;
  uint16_t inverse=c->reciprocal[r<2?0:1][get16(h+2*r)];
  for(unsigned j=0;j<256;j++) {
   uint16_t a=mul(inverse,lifted[j]^((alpha[j/8]>>(j%8))&1),d);
   for(unsigned b=0;b<d;b++) xi[at+(j*d+b)/8]|=((a>>b)&1)<<((j*d+b)%8);
  }
 }
 tim[1]=now()-t;return 0;
}
