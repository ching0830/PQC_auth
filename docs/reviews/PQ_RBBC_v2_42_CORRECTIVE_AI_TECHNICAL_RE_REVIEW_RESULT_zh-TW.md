# PQ-RBBC v2.42 corrective AI technical re-review integration record

日期：2026 年 9 月 10 日（Asia/Taipei）

## 審查對象與結論

唯讀 Codex AI-assisted technical re-review 核對下列 exact effective tree：

- implementation commit：`d6d349020f8ef22e65115130c335ea6db7e337b4`；
- parent：`81374602b5c1e304f396f54ef6f2d5b9bf2f06e9`；
- tree：`1ce0af92a84aa3e5736e9f49929a37d42301f665`；
- integration baseline：`973deee5b5603ee47ceadabd870004e214c81a96`。

本次 bounded corrective technical re-review 通過，沒有新的 blocking findings。
RR242-01／RR242-02 已在受審 commit 中修正；CR-01 在 v2.42 bounded successor
範圍內成立，CR-02 的來源更正及 historical preservation 成立。

## 獨立重審結果

- targeted：128 passed，0 failures／errors／skips；
- full regression：688 total，676 passed、12 既有 optional skips、0 failures／errors；
- recovery probes：13 組全部通過；
- extended probes：4 組完成全部 assertions；
- 8 個 post-link／pre-directory-fsync EIO 窗口各經至少兩次持續失敗 retry；失敗時
  0 successor publications，移除故障後依 chunks → journal → output 順序補足 barrier；
- wrong／stale external digest 在 fixture read 與 bounded reconstruction 前拒絕；正確
  digest 後仍使用同一 captured checkpoint bytes 完成 canonical／semantic validation；
- 34 個 durable publication boundaries 可恢復，32 個 mutation cases 拒絕；
- CR-02 三份 exact PDF revisions、78 份 sealed predecessors、v2.33 seal 與歷史 v2.41
  reservation／approval identities 均保持不變。

初次 reviewer harness 曾因 reviewer 建立的 TMPDIR parent mode 為 `0775` 而 fail closed；
修正外部 TMPDIR 為 `0700` 後，才得到上述正式 targeted／full counts。另一次 reviewer
mutation harness offset 錯誤亦在外部 harness 修正後重跑。兩者均不是產品 finding，原始
失敗紀錄仍保留於外部審查資料。

## 外部完整交付 identities

完整報告、machine findings 與其 inventory 已以 exact bytes 保存於 operator-controlled、
repository-external archive。Git 只保存本摘要，不把含本機路徑的 raw findings 當成
path-free portable evidence。

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `AI_TECHNICAL_RE_REVIEW_zh-TW.md` | 18,055 | `d232d1b5fa50e8c839aa883198c1f3909c003c33fa55eae6a0ea2f7259d36a0c` |
| `findings.json` | 19,192 | `a190e31fc0787064c62c0040e28c226239c18a3ffe2508b86b555b88904e4b3c` |
| `SHA256SUMS.txt` | 230,169 | `34b7c7b07ed6c8f0a23647f2ec529cba7416492b7add078c8107e5705af4f298` |

## Claim boundary 與下一個 gate

這次只支持 v2.42 bounded recovery／provenance successor 為 Implemented／Tested，並使
RR242-01／RR242-02 的 bounded technical-review blockers 得到處置。沒有做實體斷電、
kernel crash、remount、跨主機 filesystem qualification、production-scale relation／stream
materialization、large replay 或 proving。

本報告不是具名獨立人員的設計／密碼學核准，不是 operator authorization、正式
independent-review attestation、launch identity freeze 或 production authorization。
Filesystem／mount 的 fsync 語義、可信 producer handoff、writer quiescence、owner／mode／
ACL、既有 writable FD 與同帳號 writer 仍是外部前提。所有 production／security claims
維持 false。

下一步是由 operator 對整合後 v2.42 implementation、exact command、batch、output 與資源
窗口建立新的 resource reservation；v2.41 reservation 只保留為被拒流程的歷史。其後須由
真正具名且獨立的人員 review exact reservation bytes／SHA-256／ID 與 implementation
identities。只有該正式 review 無 blocking findings，才能建立 launch manifest candidate
並執行唯讀 preflight；仍不得因此直接啟動 production。
