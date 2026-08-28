[English](PQ_RBBC_CURRENT_HANDOFF.md)

# PQ-RBBC 目前交接 — v2.25 tree 5–7 batch

> **模組範圍：**這是 PQ-RBBC 的操作交接，不是整篇論文 roadmap。專案級背景請先讀 [../../ARCHITECTURE_zh-TW.md](../../ARCHITECTURE_zh-TW.md)、[../../RESEARCH_STATUS_zh-TW.md](../../RESEARCH_STATUS_zh-TW.md) 與 [../../ROADMAP_zh-TW.md](../../ROADMAP_zh-TW.md)。

日期：2026 年 8 月 27 日

新工作階段請先讀本文件，再讀 v2.25 release note、roadmap、artifact evidence note 與 `docs/ARTIFACT_POLICY.md`。開始前必須確認遠端最新 `main`，不可推測 open PR 已經 merge。

## 基底與已封閉邊界

v2.25 從 `aad5bed719af1db266377cb654ecc7824f34d04b` 開始，並於 `main` 的 `e823117269cde2b2428e2d71024d362a3dbc0401` merge。Planned producer index 0–7 已 materialize 並獨立 replay，共 8／18。Tree 5、6、7 雖以 bounded batch 執行，但各自具有獨立 contract、archive、row stream、output check、mutation probe 與 replay-manifest identity。

已封閉項目包含 v2.8 composer recovery、v2.9 global tail、tree 2 rebased replay、tree 1／3／4 planned replay，以及新的 tree 5–7 batch。其餘 trees、全部 72 relocations、完整 18-tree assignment replay、cross-segment identity、parent join、fork-security proof、signature benchmark 與 production closure 仍未完成。

## 必要外部 identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| v2.9 global-tail assignment | 1,004,865,028 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| v2.25 tree-5 assignment | 486,961,028 | `e8717997e1e3d85c5dbbb59602924eeafb2ae7a643433794a8cbfb9966243a18` |
| v2.25 tree-5 final replay manifest | 7,564 | `8f032ced1c11c2acd3554240ab4d6e0e061b0c04fa9b985eb20fc6184a41478f` |
| v2.25 tree-6 assignment | 486,961,028 | `e112686118690036ffef126bccbbc0fbe69c973e624d86301683aea09dec3abe` |
| v2.25 tree-6 final replay manifest | 7,564 | `0061aaaa11096c4c49af41beb0a9688b9ea4b17a29518212c53e94be7df4553e` |
| v2.25 tree-7 assignment | 486,961,028 | `3c6670f17ef484c83781d4453f976b68a6159072d5d8cfff418c0afbacf3f6db` |
| v2.25 tree-7 final replay manifest | 7,564 | `be99ea2986c7c65269d6151c5c8280266110102024ca76e2a88f5579be48ab81` |
| incremental BR1CS | 49,227,687 | `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799` |

Batch evidence SHA-256：

`0041ea819434e0099d419757fa217fcfa30b810ef391b4a4603d8aee7ad06c72`

三個 row streams 都是 8,961,160,824 encoded bytes，但這只代表各 tree 的實測值，不得推定後續 tree 也相同。

外部 v2.25 artifacts 還原後位於 `/workspace/pq_rbbc_external_artifacts_v2_25/`。使用前必須驗證所有非 pickle identities。不得反序列化下載或其他不可信 pickle；identity-bound caches 必須在本機重建。

## 驗證狀態

- batch portable evidence：6 tests passed，包含三次 external reseal；
- native／ABI／reference targeted regression：23 tests passed，105.497 秒；
- BR1CS targeted regression：5 tests passed，87.454 秒；
- affected runner／evidence／parent regression：76 tests passed，214.805 秒；一個 optional historical external-artifact reseal skipped；
- complete repository regression：250 tests passed，932.687 秒；八個 optional external-artifact tests skipped；
- parent BR1CS identity 未變：49,227,687 bytes，SHA-256 `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`。

所有 tracked／external file identities 以 v2.25 checksum inventory 為準。

## 下一個 bounded checkpoint

繼續 R1d-b2，將 tree 8、9、10 作為 bounded batch：

| Tree | Planned interval | Pre-freeze contract SHA-256 |
| --- | --- | --- |
| 8 | 234,972,873–254,451,308 | `3801f60ab7132fd850a10cf51a5f892624401988dedc64288b0807a34093ba70` |
| 9 | 254,451,309–273,929,744 | `1d64e086061717099bf1a189c34df22966ca1e67fb17ad74d373d6bdb4f9b1df` |
| 10 | 273,929,745–293,408,180 | `5d26dd745685f58b3cdfad652b9602cadf1f041d5169c4b5c4f10590cd4948aa` |

每個 target 一開始都必須使用 `stream_bytes = null`，且 target-tree formal claims 全為 false。先驗證 global-tail 與 v2.25 batch evidence，為每棵 tree 使用不同 external directory 與 cache identity，完成第一次 replay，凍結實測 stream byte count，重建 fresh cache，再完整 replay 一次後才可 seal。不得用任何 tree 的結果滿足另一棵 tree 的 identity。

## Git 與 artifact 規範

- 寫入前重新讀取遠端 `main`，並以該精確 base tree 建置。
- 不得 commit `.f193assign`、`.br1cs`、pickle、cache、resume 或 checkpoint files。
- 只上傳明確 text-file allowlist；建立 commit 前以本機 `git hash-object` 比對每個 GitHub blob SHA。
- Complete-composition、parent-join、security-proof 與 production claims 必須維持 false，直到各自 gates 真正封閉。
- Checkpoint PR 不得由 execution agent 自行 merge，除非使用者另行明確授權。
