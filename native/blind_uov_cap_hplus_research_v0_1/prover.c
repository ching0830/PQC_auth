/* H+ profile adapter. Arithmetic is shared; legacy profile export is hidden. */
#define pqsat_prover_profile_v1 pqsat_legacy_prover_profile_unused_v1
#include "../../src/pq_rbbc/blind_uov_native_prover_v0_1/prover.c"
#undef pqsat_prover_profile_v1
const char *pqsat_prover_profile_v1(void) { return "8579638797c2fa6f9ef09aef518e81213e566115e042744e5b782d8c49c5f07d"; }
