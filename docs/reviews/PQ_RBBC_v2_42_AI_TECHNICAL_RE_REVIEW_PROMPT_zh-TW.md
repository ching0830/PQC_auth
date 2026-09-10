# PQ-RBBC v2.42 AI technical re-review prompt

請對 `codex/pq-rbbc-v2-42-recovery-and-provenance` 的 **最終 exact commit** 做獨立於
實作流程的唯讀技術重審。先記錄完整 commit SHA、working-tree 狀態及 source／manifest／
test identities；若 checkout 有未 commit 變更，必須明確列出 effective tree，不能只用
branch 名稱或 command pathname digest 代表受審程式。基線為
`973deee5b5603ee47ceadabd870004e214c81a96`。

本 prompt 是審查請求，**不是審查結果、核准、簽章或 attestation**。
Codex AI-assisted review 不等於最終要求的具名獨立人員核准。不要將本文件轉寫成
`PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-4`，不要填入假的 reviewer。

## 必讀資料

- `AGENTS.md`、文件 ownership／artifact policy 及 current handoff。
- 原 review：`/tmp/pq-rbbc-v241-crypto-review-zRKfCkWS/CRYPTOGRAPHIC_REVIEW_zh-TW.md`、
  machine-readable review JSON、`probes.py`／`probe-results.json`。若外部目錄已不存在，
  先依新 preservation evidence 記錄的 identities 取得 exact copies。
- `docs/artifacts/PQ_RBBC_v2_42_RECOVERY_AND_PROVENANCE_zh-TW.md`、
  `docs/specs/PQ_RBBC_v2_42_PROVENANCE_ERRATUM_zh-TW.md`。
- 三份新 source、兩份新 manifests、兩份新 tests、
  `artifacts/metadata/cap_recovery_v2_42/` 與新 checksum inventory。
- v2.38 historical writer／codec／checkpoint validator，v2.41 snapshot-contract
  corrective source、launch validator／schemas／portable evidence，sealed v2.33 spec。

## 必須獨立重現的 CR-01／P2

請自行安排 failure injection，避免只重跑作者 tests 後沿用其結論：

1. Chunk publication 已完成，下一份 prefix checkpoint 尚未提交。Resume 必須先
   核對 externally supplied latest checkpoint SHA，再從 exact fixtures 重新計算 chunk。
   檢查只接受下一個 ordinal、正確 stage 與 exact bytes／SHA；不能只看 filename 或
   checkpoint 裡自報的 hash。
2. 15 個 chunks 與 `0015-prefix-v2_42.json` 均存在，但 `complete=false`。必須能
   完成 complete checkpoint／index／evidence。分別在這三次 publication 之間中斷，
   並重複 resume；結果應逐 byte 相同，既有 files/inodes 不被覆寫。
3. 對 orphan 改 payload、SHA 對應內容、ordinal、stage、first item、count、profile、
   trailing bytes；放入陌生、跳號、多份 orphan、缺失 committed chunk。全部 fail closed。
4. 對 journal 做 duplicate keys、invalid UTF-8、noncanonical encoding、bool/int/float
   混淆、prefix chain／previous checkpoint mutation、premature complete、stale externally
   supplied digest；正確 self-reported SHA 仍不得挽救非法 state。
5. 對 output、chunks、journal 與 final paths 放入 symlink、dangling symlink、hardlink、
   FIFO；在 publication 前插入競爭 writer；測試兩個 processes 同時 resume、直接 process
   death、link 後退出。確認 absence/existence publication 原子且 exclusive，沒有 truncate／
   replace fallback。Linux `O_TMPFILE`／procfs／linkat 不支援或 fsync 失敗應拒絕。
6. 檢查 pathname mutation 前後 identity、parse 與 semantic validation 都使用 captured
   bytes；不得將 metadata、directory flock 或一次成功 test 誇大為 filesystem 強不可變性。
   Trusted writer／ACL／writable FD／mount 假設必須清楚。第一份 prefix 之前的初始化失敗
   不宣稱可 resume；v2.38 歷史 outputs 也不能原地升格為新 journal。

## 必須核對的 CR-02／P3

直接檢查下列 **exact PDF revision bytes**，勿只依網站最新版或表格數字相同判斷來源：

- BAVC：ePrint 2024/490，2025-03-31 revision，§3.1／§4。
- Generic TCitH comparison：ePrint 2024/541，2024-11-08 revision，Table 7，印刷頁 29。
  這是 RSD support-decomposition signatures；Table 4 是 MinRank，都不是 Blind-UOV
  parameter table。
- Blind-UOV CAP parameters：ePrint 2025/895，2025-10-31 revision，Table 2，印刷頁 20；
  NIST III／Shorter／TCitH 為 `(2,4096),(16,2048),tau=18,T_open=174,w=9,w_tot=13.9`。
- Blind-UOV／MAYO performance：同一 revision 的 Table 4，印刷頁 25。

核對 manifest 的 revision／bytes／SHA-256 及 PDF verifier 的 size limit、single capture、
錯 revision／role／table mutation rejection。確認 sealed v2.33 source／PDF／seal 未改寫，
沒有把 paper performance 或共用 tree 數值轉成 fork benchmark／security proof。

## Regression 與歷史保存

從 artifact note 執行 targeted command 及完整 baseline：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

Passed、failures、errors、skipped 分開報告，保存 skip reasons。獨立核對 78 份 pinned
predecessors 與 baseline Git objects，尤其 v2.38／39 manifests、portable evidence、
checksums 及 v2.33 spec。V2.41 inventory 中 mutable handoff 那一項使用
`1a1d576:<path>`，不得改寫 checksum 遷就 current handoff。

V2.41 operator reservation 與 approval record 是被拒流程的歷史，只核對 identities，
不要覆寫、重新核准或當成 v2.42 authorization。Private operator 原文不應拷入 Git。
原 review probes 的副本應輸出到新的 external directory；兩個 v2.38 failure probes
仍然是歷史 failure，不應誤報為 v2.38 已修復。

## Claim boundary 與交付

不要啟動 production-prefreeze、large replay 或 proving；不要產生真實 reservation、
independent attestation、launch candidate 或正式 identity freeze。完整 CAP acceptance、
adversarial extraction／unique mask、concrete Anemoi ROM／QROM、PoW/query-loss accounting、
production materialization／scale qualification、parent join 等缺口仍須各自封閉。

請輸出繁體中文報告及 machine-readable findings，逐項列 severity、exact location、
trigger、observed／expected、重現步驟、identity、修正建議與驗證限制。明確指出 CR-01、
CR-02 是否在 successor 中得到滿足，以及有無新 blocking findings。

即使此 AI technical re-review 無 blocking findings，仍須按序取得針對最終 effective tree
的新 v2.42 operator reservation，以及綁定 **exact reservation bytes／SHA-256／id、batch、
command、implementation commit／source identities** 的具名 independent human review。
只有該真正 review 無 blocking findings，才可生成 launch manifest candidate；正式 freeze
與 production execution 又是後續獨立 gates。
