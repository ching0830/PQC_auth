# PQ-RBBC v2.41 AI technical re-review integration record

日期：2026 年 9 月 9 日（Asia/Taipei）

## 審查範圍與結論

唯讀 AI-assisted technical re-review 核對 effective tree：

- implementation commit：`1b89ebea12110a655dc1dc6abb5a00d4bd38a338`；
- corrective commit：`1a1d576ef3868a1c997063db80171c9f2cb4f5f8`；
- base：`3885b01d2b7bccd8ae0cb5e465c4b63aa48d4442`。

新 findings 為空。前次 P2 已以明確縮限 snapshot contract 處置：identity、strict
parse、binding 與 validation 共用 single-open／single bounded-read 所得的 immutable
`Snapshot.raw`；filesystem metadata 只是 best-effort mutation signal，不構成強不可變性
證明。Future executor 必須消費相同 `CandidateSet` snapshots，不得重新開啟 pathname。

## 獨立重審結果

- targeted：69 passed，0 failures/errors/skips；
- full regression：641 total，629 passed、12 既有 optional skips、0 failures/errors；
- 八項獨立 probe groups：17/17 passed；
- corrective probe groups：4/4 passed；
- 額外 version/profile/lower-bound cases：17/17 passed；
- 19 份 v2.38/v2.39 historical identities、v2.38/v2.39/v2.41 inventories 與 negative
  portable rebuild 均相符。

暫存完整報告在審查時的 identity：

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `AI_TECHNICAL_RE_REVIEW_zh-TW.md` | 23,637 | `34ca21f07a1adb150692712b4d2227bb0d0cb874fdda6e2d5f951e59066250de` |
| `findings.json` | 1,309 | `bf3804fa9ffba116b83a27ed7801b99967ef510d0079f16d3c7b2cd020df8efc` |
| `validation-summary.json` | 5,744 | `b54a29bfa33e68a77af3123f01169a3f59ee4e755facdbb22623f6ec2b32c89c` |
| `corrective-probe-results.json` | 2,987 | `5b74c62e7ba2433598a32375dc7eba04ec43d016bdf1eb6665f89c2b45cd5512` |

本文件保存審查摘要及暫存報告 identities，不把 `/tmp` 路徑當作持久 artifact location，
也不加入或改寫 v2.41 sealed checksum inventory。

V2.41 checksum inventory 內的 mutable current-handoff entry 保留為歷史 identity，對應
`1a1d576ef3868a1c997063db80171c9f2cb4f5f8:docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`：
24,839 bytes、SHA-256
`689f330692cc3110a422902ce451c116bf0640f13ce71a01bbbb41deab11c3cf`。Integration 後的
current handoff 依文件政策繼續更新，因此不要求 current bytes 符合該歷史 entry；inventory
其餘 15 項仍可直接對 current tree 驗證。不得為消除這個預期差異而回寫歷史 checksum。

## Claim boundary 與下一個 gate

這是 AI-assisted engineering review，不是 external human cryptographic review、operator
approval、independent-review attestation、launch identity freeze 或 execution authorization。
Trusted producer handoff、writer quiescence、inode owner／mode／ACL、既有 writable FD 與
mount namespace 仍是部署前提。所有 production/security/large-run claims 維持 false。

下一步是先 provision repository 外的 trusted artifact root，再由真實 operator 建立
exact v2.41 resource reservation；合格且獨立的 human reviewer 必須審查 exact commit、
reservation bytes、batch 與 command binding。兩者成立後才可 author launch manifest
candidate 並執行唯讀 preflight；仍不得因此啟動 production。
