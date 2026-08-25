# PQ-RBBC v2.12 production split-tail assignment

The production assignment is the frozen v2.9 archive, reconstructed from its
21 byte-exact Library chunks:

- file: `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign`;
- bytes: 1,004,865,028;
- wires: 40,194,596;
- archive SHA-256:
  `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`;
- assignment-body SHA-256:
  `358266d106a1ac01cacb7c19c9bff1a7da2acceeb580a1d54462f31986cba925`;
- row-stream SHA-256:
  `c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`.

The v2.12 observer does not create a second production assignment. It replays
the same archive through the unchanged canonical row generator and records the
logical Phase-A/Phase-B boundary.

Executed command:

```bash
python -u pq_rbbc_cap_production_split_tail.py \
  --archive production_v2_9_parts/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign \
  --source-manifest pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --manifest production_split_v2_12/pq_rbbc_cap_production_split_tail_manifest_v2_12.json
```

Result:

- replay time: 812.435827491001 seconds;
- verification failures: 0;
- external assertions: 0;
- exact boundary mutations: 5/5 rejected;
- peak RSS: 1,023,720 KiB.

The approximately one-gigabyte archive and its already preserved 48 MB chunks
are not duplicated in the compact v2.12 source release.  The v2.12 manifest
contains the frozen archive identity and all new split-tail evidence.
