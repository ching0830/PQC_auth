# PQ-RBBC v2.7 degree-13 assignment parts

The canonical file `pq_rbbc_cap_shard_assignment_4096_v2_7.f193assign` is
994,739,228 bytes and has SHA-256:

`e4dea88f7f47849cd858d3ba2d5110bd1893efb1ac4544a8b2cb8a0e7fa87aa1`

It is distributed as 23 ordered parts. Parts 00 through 21 are exactly
45,000,000 bytes; part 22 is 4,739,228 bytes.

| Part | SHA-256 |
| --- | --- |
| `part-00` | `e60bb7fbd30bf75235bf293a5909b21d1fe688ef2d024a5a24291db7f37f8ad5` |
| `part-01` | `4ed253ab6bfb9a79f9cce7f504552987de588539da23f29f6e4577636a3d54ca` |
| `part-02` | `57808d09e48bb91327715791efdeb574f8eb82deebfdd96fc252a06e05e207d5` |
| `part-03` | `1121f03f413d0da3b87575361bd05d5cf1cb4e6cd368a53aa6be8a4a18e97779` |
| `part-04` | `a43666fbd95f33ea5a390af12418fbd8dda756ea23ec0406f304f1df51077497` |
| `part-05` | `4e23a8ed402e5b5a9536a49c4af5c9bcfc29cbc6e89a7b85c68b441fac0d7672` |
| `part-06` | `f2526154b0543b0cd15e8ec08d450ebe1ae6289537b440dae6f433f85a253057` |
| `part-07` | `15931f419d230f6a2e707f4c44ab5c9d3eaa261ef3c78cbf3d3b7a1a76c0558c` |
| `part-08` | `5e542ce88c3107c1cb1cf4bf579c40486348bb54ef47f27714f73380b602939e` |
| `part-09` | `93adc9b7884ded28d45dcd755121cd2184e076af1674c9e3171bf5ad6795d630` |
| `part-10` | `97065d96cdf92f6b090cedc5f574f88365f46c099a2ebc8759b37a2c67fc5b08` |
| `part-11` | `dea65f0d849b63334ee1d1f97c63b77f4bbd85454b5f55f26ba5a8f945b9bbfa` |
| `part-12` | `4c9ed33ba0126a1bd76f6e9bca7057aace3d6adfbe70718b4d2aec56c26c69a4` |
| `part-13` | `873f202ba566bffb25da22c15f1ee1ed043595f440b8dfa89ba6b03505e3bb0c` |
| `part-14` | `abc052127172e709ca4251cd8cda14881571cceeb3df6aab09f0cb6bef9ccc2e` |
| `part-15` | `5eb806b68f8c04023bb4d3fdb631171b675fc561056dd94c7647aca3cfc41eb2` |
| `part-16` | `6cbbbe2ab6db6b6b9fc75f11bc2f4d5a9172dd44a5d285a91d26b87917c8ca75` |
| `part-17` | `847979186b602c3e450e7b5a58a281145568cb12cce7850106b1c4c7f443b592` |
| `part-18` | `cd7fe348ac9b69f91a35c314b9c4842fa41cbd4fc95ebca796611e833ccc425f` |
| `part-19` | `e268608db469378bb38b99aee01e0e89c55799eefc196e4ea9e11bef96e38c31` |
| `part-20` | `1188582a27f7cdc421b811bc59674d01238536ec426a06111021e5513b9e1d8b` |
| `part-21` | `e6d246a37e610135fc7d025e5b89bdb7edbfa655b8ba61f74eeec7efc366eb13` |
| `part-22` | `d6c94f08ff679faf28db86305983527470bb3ba4c6b17dde026639dabd471aad` |

Reassemble in lexical order:

```sh
cat pq_rbbc_cap_shard_assignment_4096_v2_7.f193assign.part-* > pq_rbbc_cap_shard_assignment_4096_v2_7.f193assign
sha256sum pq_rbbc_cap_shard_assignment_4096_v2_7.f193assign
```

The result must be exactly 994,739,228 bytes and match the whole-file digest
above before it is opened by the assignment reader.
