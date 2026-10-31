/* PUBLIC deterministic tuple controls, never a ticket/proof interface. */
#include "opening.c"
#include <stdio.h>
int main(void) {
 uint8_t salt[48],seed[24],out[192];
 for(unsigned i=0;i<48;i++) salt[i]=(uint8_t)i;
 for(unsigned i=0;i<24;i++) seed[i]=(uint8_t)(i+64);
 const char *domains[]={"PQSAT-BUOV-CAP-HPLUS-0.1/SEED-DERIVE",
  "PQSAT-BUOV-CAP-HPLUS-0.1/LEAF-COMMIT","PQSAT-BUOV-CAP-HPLUS-0.1/TAPE-EXPAND"};
 for(unsigned kind=0;kind<3;kind++) {
  size_t n=input(out,domains[kind],salt,42,2,2047,seed,kind!=0);
  if(n>sizeof(out)) return 1;
  printf("%u %zu ",kind,n);
  for(size_t i=0;i<n;i++) printf("%02x",out[i]);
  putchar('\n');
 }
 return 0;
}
