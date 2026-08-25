# PQ-RBBC v2.11 reduced split-tail assignment

The checkpoint contains one fixed-width GF(2^193) assignment archive for the
non-secure reduced global-tail Phase-A/Phase-B contract.

## File

- `pq_rbbc_cap_split_tail_reduced_v2_11.f193assign`
  - 24,992 wires
  - 624,928 bytes
  - body SHA-256
    `ea4165dd32323a0ecf34cd21d7515571fdd6682f857266c0f3608aa1a4fd703c`
  - archive SHA-256
    `0915410fac94d6ab8ae9dcab487af7d8aca98aa187c6960e3472e77db990edc0`

Every wire is encoded as one canonical 25-byte little-endian GF(2^193)
element after the 128-byte assignment header.

## Reproduction

```bash
python -u pq_rbbc_cap_split_tail.py \
  --archive split_v2_11/pq_rbbc_cap_split_tail_reduced_v2_11.f193assign \
  --manifest split_v2_11/pq_rbbc_cap_split_tail_manifest_v2_11.json \
  --workers 2 \
  --replace
```

The command independently generates the canonical assignment, generates the
split-observed archive, compares the complete row-stream and assignment-body
digests, replays every row through mmap, validates the exact phase ranges, and
rejects four exact boundary-wire mutations.

This archive is an engineering fixture.  It has one consistency point and
does not establish the production two-point split or producer-to-tail point
wire identity.
