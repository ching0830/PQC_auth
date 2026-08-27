# PQ-RBBC v2.25 — Tree-5 through tree-7 batch planned recovery

Date: 27 August 2026

## Outcome

R1d-b2 advanced through a bounded three-tree batch.  Tree indices 5, 6, and 7
were each materialized at their frozen v2.16 namespace interval, replayed under
their own final contract and fresh identity-bound cache, matched against all
four recovered global-tail consumers, and sealed with independent identities.
The batch evidence is path-free; assignments, caches, resume state, global
tail, and BR1CS remain outside Git.

## Exact results

| Tree | Planned wire interval | Final contract SHA-256 | Assignment SHA-256 | Row-stream SHA-256 | Component SHA-256 |
| --- | --- | --- | --- | --- | --- |
| 5 | 176,537,565–196,016,000 | `49694ee2229c0a99731510b3b9242c7863e2663a0684061fa821132266d27e58` | `e8717997e1e3d85c5dbbb59602924eeafb2ae7a643433794a8cbfb9966243a18` | `34683185ba262e73397532c944b6f70b23ea59a55786535e0cec8473c58f0375` | `a3d74bcb6750d3fe8b4e483171da8cdd20074c8676c80fecb9fa4b400f484779` |
| 6 | 196,016,001–215,494,436 | `119d4e6dbe9d6003eac74df3299bfd5e52f6c764c8b3d9bb6cee59b983698028` | `e112686118690036ffef126bccbbc0fbe69c973e624d86301683aea09dec3abe` | `0a08cb7f018135d99dfad6b69712659f71a220424e89987daaea9c74fb6fea25` | `520928a648368a71d6ce8a82889ca164d15d14b9a62cb3e8505023bfc852b0c6` |
| 7 | 215,494,437–234,972,872 | `71e8faf784f9c489ea82b09e53799dc7ff205a035baac7e71ec9f0068154b396` | `3c6670f17ef484c83781d4453f976b68a6159072d5d8cfff418c0afbacf3f6db` | `f34bb645f31c8dee51f0a8706c595df07ed465136cfeaec5a20a85cf54328992` | `88449591a1a221ebda29235b2e2451b893b33605a1468fce8bbc7dce08705c2b` |

Every tree has 19,478,436 local wires, 25,666,386 constraint rows, a
486,961,028-byte assignment with a 486,960,900-byte body, and an independently
observed 8,961,160,824-byte encoded row stream.  Equal stream sizes are three
observations, not a rule for later trees.

Final replay-manifest SHA-256 values are, in tree order:

- tree 5: `8f032ced1c11c2acd3554240ab4d6e0e061b0c04fa9b985eb20fc6184a41478f`;
- tree 6: `0061aaaa11096c4c49af41beb0a9688b9ea4b17a29518212c53e94be7df4553e`;
- tree 7: `be99ea2986c7c65269d6151c5c8280266110102024ca76e2a88f5579be48ab81`.

The path-free batch evidence SHA-256 is
`0041ea819434e0099d419757fa217fcfa30b810ef391b4a4603d8aee7ad06c72`.

## Frozen-contract procedure

Each pre-freeze contract kept `stream_bytes = null` and all formal target-tree
claims false.  Only a complete replay supplied the observed byte count.  The
runner then froze that count into the tree-specific final contract, rebuilt a
fresh cache, reused the read-only archive, and replayed all rows again.  The
final verification times were 649.187, 655.431, and 701.345 seconds for trees
5, 6, and 7 respectively; generation time was zero in every final run.

Each final replay reports zero failed rows and zero external assertions, exact
matches for all four outputs, and rejection of six stale-witness plus three
point mutations.  Configuration mutation probes also fail closed.

## Claim boundary

Newly true are the assignment-materialized and full-replay-closed claims for
trees 5, 6, and 7.  `materialized_planned_tree_indices` is now `[0,1,2,3,4,5,6,7]`
and the count is 8.  Remaining producer materialization, all 72 relocations,
the complete 18-tree assignment, cross-segment identity, parent join,
fork-security proof, and `production_closed` remain false.

## Validation

The evidence suite resealed all three external archives and passed 6 tests.
Parent source regressions passed 23 tests; BR1CS regressions passed 5 tests.
The affected runner/evidence/parent suite passed 76 tests in 214.805 seconds
with one optional historical external-artifact reseal skipped.  The complete
repository regression passed 250 tests in 932.687 seconds with eight optional
external-artifact tests skipped.  The parent BR1CS remains 49,227,687 bytes
with unchanged SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Next checkpoint

Continue with another bounded batch: tree indices 8, 9, and 10.  Their initial
contracts must keep row-stream bytes unknown and all production claims false
until each first replay independently observes its encoded size.
