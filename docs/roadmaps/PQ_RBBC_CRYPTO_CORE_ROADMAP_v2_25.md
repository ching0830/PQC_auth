# PQ-RBBC crypto-core roadmap — after v2.25

## Gate status

| Gate | Status |
| --- | --- |
| v2.8 composer recovery and v2.9 global-tail replay | Complete |
| Planned producer positions materialized | 8 of 18: indices 0 through 7 |
| v2.25 tree-index-5-through-7 batch | Complete, individually sealed |
| Remaining planned-offset producers | Open: indices 8 through 17 |
| All 72 output relocations | Open |
| Complete 18-tree assignment replay | Open |
| Parent CAP-to-H-RBBC join | Open |
| Fork-security and reduction proof work | Open |
| Production closure | False |

## Completed v2.25 batch

Trees 5, 6, and 7 each closed under a distinct final contract after the
two-stage pre-freeze/frozen replay.  Each has 25,666,386 rows, 19,478,436
wires, a 486,961,028-byte external assignment, exact matches for four
global-tail consumers, zero external assertions, and 6+3 rejected mutations.
The portable batch seal binds every tree independently; it does not create an
aggregate 18-tree claim.

## Next bounded batch — trees 8, 9, and 10

| Tree | Planned wire interval | Output starts | Initial stream-unfrozen contract SHA-256 |
| --- | --- | --- | --- |
| 8 | 234,972,873–254,451,308 | 253,583,673; 254,374,201; 254,376,249; 254,446,677 | `3801f60ab7132fd850a10cf51a5f892624401988dedc64288b0807a34093ba70` |
| 9 | 254,451,309–273,929,744 | 273,062,109; 273,852,637; 273,854,685; 273,925,113 | `1d64e086061717099bf1a189c34df22966ca1e67fb17ad74d373d6bdb4f9b1df` |
| 10 | 273,929,745–293,408,180 | 292,540,545; 293,331,073; 293,333,121; 293,403,549 | `5d26dd745685f58b3cdfad652b9602cadf1f041d5169c4b5c4f10590cd4948aa` |

All three targets have 2,048 leaves, extension degree 12, 19,478,436 wires,
and 25,666,386 rows.  Row-stream bytes remain unknown.  Do not copy the
8,961,160,824-byte observation from trees 3 through 7 into an initial
contract.

Before execution, verify the v2.20 global-tail archive, v2.25 batch evidence,
frozen namespace, free space, and checkpoint/resume fixtures.  Use separate
external directories and cache identities per tree.  For every tree: complete
the pre-freeze replay, freeze observed stream bytes, rebuild a fresh cache,
repeat the full replay, compare four outputs, and reject stale-witness, point,
identity, offset, archive, and configuration mutations.

## Later work

Continue with bounded batches until indices 8 through 17 are independently
sealed.  Only after all 18 positions and all 72 relocations are closed may the
complete assignment and parent join be attempted.  Fork-security and reduction
arguments must then be revalidated against the final frozen semantics.  No
producer batch alone establishes production security.
