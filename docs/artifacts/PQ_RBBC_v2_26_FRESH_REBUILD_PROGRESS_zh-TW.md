# PQ-RBBC v2.26 fresh rebuild進度

日期：2026 年8月31日

本文件記錄為tree 8–10 bounded checkpoint補齊external prerequisites的本機
fresh rebuild進度。它不是新的production closure、完整18-tree replay或parent
join evidence。所有binary assignment、BR1CS、pickle、cache與resume state均位於
Git之外的本機external directory。

## Incremental BR1CS

- bytes：49,227,687；
- SHA-256：`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`；
- 結果：與v2.25 frozen identity精確一致。

## Composer recovery

- checkpoint bytes：19,524,889；
- checkpoint SHA-256：`01244778354875ff4f410bb5ca53a486369eb1760872c457f624108fc922279a`；
- composition document SHA-256：
  `a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163`；
- locally serialized execution-cache bytes：35,509,449；
- locally serialized execution-cache SHA-256：
  `4fc980b3408d00418fed15f282a80a2c932b829c002146cc80adb609b3814a38`。

Cache內容通過production identity loader，但pickle whole-file digest因本次Python
serialization環境而不同於歷史cache。它只作為trusted local cache使用，不視為
歷史pickle artifact，也不得分發或commit。

## v2.20 global-tail fresh rebuild

- assignment bytes：1,004,865,028；
- assignment SHA-256：
  `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`；
- rows／wires：56,806,711／40,194,596；
- row-stream SHA-256：
  `c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`；
- verification failures／external assertions：0／0；
- stale-witness probes：6/6 rejected；
- fresh generation／verification：1,878.385／579.005秒；
- fresh peak RSS：1,565,008 KiB；
- fresh manifest SHA-256：
  `ba46335a3fd40f701f231535248206474691d1e67e5b1427bbaf3c80f59f341e`。

Fresh manifest的security projection與historical manifest完全相同。原v2.20
sealer因fresh performance fields與歷史量測不同而fail closed；沒有改寫fresh
量測。另產生path-free fresh-rebuild evidence，SHA-256為
`658f21b0eaf8c04f04ce2c2c1216563a268e1ea736d9453c4f0e914c76d142f2`，
明確保持historical-performance-reproduced claim為false。

## v2.25 tree 5 fresh rebuild

- planned interval：176,537,565–196,016,000；
- assignment bytes：486,961,028；
- assignment SHA-256：
  `e8717997e1e3d85c5dbbb59602924eeafb2ae7a643433794a8cbfb9966243a18`；
- body SHA-256：
  `7256cd78339cb81c5532841eee1af6df588ddef1b6ee41c5b950345b86dc1fd2`；
- row-stream bytes：8,961,160,824；
- row-stream SHA-256：
  `34683185ba262e73397532c944b6f70b23ea59a55786535e0cec8473c58f0375`；
- tree-component SHA-256：
  `a3d74bcb6750d3fe8b4e483171da8cdd20074c8676c80fecb9fa4b400f484779`；
- replayed rows：25,666,386；
- verification failures／external assertions：0／0；
- output matches：4/4 exact；
- stale-witness／point mutations：6/6及3/3 rejected；
- fresh generation／verification：320.716／455.342秒；
- fresh replay manifest SHA-256：
  `b2c264e833c1c23be8c153449fe5630c5dd2e9815543ccf1aa10fc2c140ced65`。

Assignment、body、row stream及tree component皆與歷史v2.25 identity精確一致。
Fresh replay manifest因performance fields不同，不宣稱重現歷史manifest bytes。

## Tree 8–10 bounded frozen replay

Tree 8、9、10均先以各自獨立directory、artifact tag及fresh local cache完成
pre-freeze replay，再把該tree自身觀測到的row-stream bytes凍結至final contract，
最後用另一個fresh cache完成第二次完整replay。沒有跨tree沿用observed stream
identity。

- tree 8 frozen manifest SHA-256：
  `6e7f4df14772370727940b9367430a8ad37d3eaa4e29a97f174133922c8e69cc`；
- tree 9 frozen manifest SHA-256：
  `f82ce1c1733d30e9c49e69551eeee80698230f01f4857b868764ff51d8f8b806`；
- tree 10 frozen manifest SHA-256：
  `8c56f7c426ad1f632af36c0d4e40536ff5726a5875734d7014d0b9c429fb067d`；
- tree 8／9 row-stream bytes：8,961,160,824（各自觀測及驗證）；
- tree 10 row-stream bytes：8,986,785,870；
- 每棵tree：25,666,386 rows、4/4 exact outputs、0 verification failures、
  0 external assertions、6/6 stale-witness及3/3 point mutations rejected；
- 三次frozen replay均為fresh cache，沒有resume。

Path-free bounded recovery evidence位於
`artifacts/metadata/tree8_10_bounded_recovery_v2_26/`，SHA-256為
`9a8ad3b2b5af242ef6ee6b33d99035505c1b8a5764d84766ce6d44f9cd00895f`。
它只把materialized planned tree推進至indices 0–10。Remaining producers、
all 72 relocations、complete 18-tree replay、cross-segment identity、parent join、
fork-security revalidation與production closure仍全部為false。

## v2.25 tree 6與tree 7 fresh rebuild

Tree 6 assignment SHA-256為
`e112686118690036ffef126bccbbc0fbe69c973e624d86301683aea09dec3abe`，
row-stream SHA-256為
`0a08cb7f018135d99dfad6b69712659f71a220424e89987daaea9c74fb6fea25`，
tree-component SHA-256為
`520928a648368a71d6ce8a82889ca164d15d14b9a62cb3e8505023bfc852b0c6`。
Fresh replay manifest SHA-256為
`f4b829092817806986801071bf486d11294c70e6cce6f648489fe63a8cb5120c`。

Tree 7 assignment SHA-256為
`3c6670f17ef484c83781d4453f976b68a6159072d5d8cfff418c0afbacf3f6db`，
row-stream SHA-256為
`f34bb645f31c8dee51f0a8706c595df07ed465136cfeaec5a20a85cf54328992`，
tree-component SHA-256為
`88449591a1a221ebda29235b2e2451b893b33605a1468fce8bbc7dce08705c2b`。
Fresh replay manifest SHA-256為
`f1bfc1cadeeddfcc67841d02717204ac53960bdd5d69339cf343e8b9800969dd`。

兩棵tree各自完成25,666,386-row replay、4/4 exact output matches、零
verification failures、零external assertions，以及6/6 stale-witness與3/3
point-mutation rejections。Tree 5–7 assignments、row streams及tree components
均精確重現歷史v2.25 cryptographic identities；fresh manifests因performance
fields不同而不宣稱重現歷史manifest bytes。

## Tree 5–7 performance-normalized fresh evidence

Path-free fresh batch evidence已產生，SHA-256為
`068a8e64122cca0a833ddf5ecb60a7f1f39bacce1162c7396253cc171b3ef5b0`。
它逐tree綁定historical與fresh replay-manifest identities、contract、assignment、
body、row stream、component、rows、outputs及mutation結果；generation、
verification與peak RSS只記為本次environment measurements。
`historical_performance_reproduced`、remaining producers、all 72 relocations、
complete replay、parent join及production closure均維持false。

Complete 18-tree assignment、all 72 relocations、cross-segment identity、parent
CAP-to-H-RBBC join、fork-security proof與production closure全部維持false。

## Tree 8–10 environment preflight

V2.26 checker已驗證rebuilt global-tail assignment、incremental BR1CS、tracked
historical global-tail與tree 5–7 seals、fresh global-tail evidence、fresh tree 5–7
batch evidence，以及tree 5–7 external archives。Environment report回報
`safe_to_start_large_replay = true`與`large_replay_started = false`。Tree 8–10
initial contracts仍保持`stream_bytes = null`，所有target formal claims仍為false。
