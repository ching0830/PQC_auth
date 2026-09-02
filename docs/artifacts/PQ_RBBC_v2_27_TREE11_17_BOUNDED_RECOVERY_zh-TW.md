# PQ-RBBC v2.27 tree 11–17 bounded recovery

日期：2026 年 9 月 3 日

Tree 11至17各自使用獨立external directory、pre-freeze cache與frozen fresh
cache完成兩次完整replay。每棵tree的initial contract均以`stream_bytes = null`
開始；final contract只採用同一棵tree第一次完整replay的觀測值，不跨tree引用。

## Frozen manifest identities

| Tree | Frozen manifest SHA-256 | Row-stream bytes |
| ---: | --- | ---: |
| 11 | `f83b52916da3c2bf0448ade8e859fca0a50284dfd1b9a4684d33c65eb15bda59` | 8,986,785,870 |
| 12 | `a4142a567841c6e824cf913ad3b064e9a05db4ca02df6a2485e3dab4f4ecf93b` | 8,986,785,870 |
| 13 | `23000f9dbee82a6e8e810c2b03ac87b40038f6cf83e8d55220cf4c2ce9e4513a` | 8,986,785,870 |
| 14 | `80382bf0d2a001630fb4167f24a393a094b4515db44a61c6e54032e066a1ef26` | 8,986,785,870 |
| 15 | `0315e90986ecce28d3cad15e110ff1d8f9c05f5d5ac0f926a0037422a952b1d5` | 8,986,785,870 |
| 16 | `9ee5f95d9c9f215238935c30eaea457edc7af93d43c52099caf33f76c7b698df` | 8,986,785,870 |
| 17 | `4ae463d07bc05cbbdaf045c6a64bb4fc9b6f4f860440542ad7f4f35c38d8f251` | 8,986,785,870 |

七棵tree各自完成25,666,386-row replay、4/4 exact output matches、零
verification failures、零external assertions、6/6 stale-witness與3/3
point-mutation rejections。Frozen replay均使用fresh cache且沒有resume。

## Portable evidence

Path-free evidence：
`artifacts/metadata/tree11_17_bounded_recovery_v2_27/pq_rbbc_cap_tree11_17_bounded_recovery_evidence_v2_27.json`

SHA-256：
`718dad0fa9c6291e7b4f0c1848121935bab000da485c011dd539f9d377e8cbde`

Evidence鏈結v2.26 tree 8–10 seal，並把individually materialized planned tree
indices固定為0至17。因此18個producer positions與72個individual output
relocations已關閉。這不等同aggregate 18-tree assignment replay；complete replay、
cross-segment identity、parent CAP-to-H-RBBC join、fork-security revalidation與
production closure仍全部為false。

所有assignment、BR1CS、pickle、cache、resume state與logs均保留在Git之外。
