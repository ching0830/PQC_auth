# PQ-RBBC v2.42 corrective AI technical re-review prompt

請在新的獨立、乾淨 worktree，唯讀審查呼叫者指定的 **完整 exact commit SHA**，
branch 為 `codex/pq-rbbc-v2-42-recovery-and-provenance`。該 corrective commit 的
parent 必須是 `81374602b5c1e304f396f54ef6f2d5b9bf2f06e9`；先記錄 commit、parent、
tree SHA、working-tree 狀態，以及 source／manifests／tests identities。不要用移動中的
branch tip 代替指定 SHA。若未指定 exact SHA 或 checkout 不乾淨，先解決受審對象問題。
本文件不內嵌自身所在 commit 的 SHA；完整 SHA 由提交後的外部交接 prompt 提供。

本次是針對 RR242-01／P2、RR242-02／P3 的 corrective effective tree 重審。
這是審查請求，並非結果、核准、簽章、attestation 或 operator authorization。
不得沿用實作者測試結論；必須自行設計 probes 並重跑測試。

## 必讀與受保護證據

完整遵循同目錄的 [原 v2.42 re-review prompt](PQ_RBBC_v2_42_AI_TECHNICAL_RE_REVIEW_PROMPT_zh-TW.md)，
包含 CR-01／CR-02、全部 failure windows、filesystem 假設、歷史保存及 claim boundary；
本文件補充 corrective 順序與新證據要求。另讀 AGENTS.md、文件／artifact policy、
current handoff、v2.42 artifact note、三份 source、兩份 tests、兩份 manifests、
三份 metadata 與 v2.42 checksum inventory。

前次 AI re-review 必讀原檔位於 `/tmp/pq-rbbc-v242-ai-rereview-Cdl2UHKZ/`：

| 檔案 | bytes | SHA-256 |
| --- | ---: | --- |
| `AI_TECHNICAL_RE_REVIEW_zh-TW.md` | 19959 | `ded8c9a7fcb45b87183b1d5add2093cb97c4ba358741ab343c149f29c39fd083` |
| `findings.json` | 27830 | `46c5487ee1b18024c62c0040e28c226239c18a3ffe2508b86b555b88904e4b3c` |

先驗證 identity；若原位置不存在，取得 exact copies 後再使用。不要改寫原報告、probes、
log 或原 qualification。原 CR-02 判定可作待核對的歷史，不能代替本次核對。

## RR242-01：既存 entry 的 durability barrier

1. 在真實 link 成功後、parent-directory fsync 前注入 `EIO`，確認 entry 已存在而
   exception 傳出。分別涵蓋 orphan chunk（含最後一個 chunk）、prefix checkpoint
   （含 prefix 0 與 prefix 15）、complete、index、evidence。
2. Retry 時讓相關 parent-directory fsync **持續失敗**，至少重試兩次。每次必須拒絕，
   不能發布 successor checkpoint、下一個 final artifact，或在已有全部 final files
   時回報完成。檢查 fsync 確實被呼叫，不能把「沒呼叫所以沒拋錯」算成成功。
3. 移除故障後捕捉實際順序：先驗證既存 entry，使用 pinned／validated chunks、journal、
   output directory FD 補足適當的 barrier；既存 chunks 必須在 journal 前持久化。
   orphan 再驗證與 chunks-directory fsync 成功後，才可發布 successor prefix。
   existing complete／index／evidence 也必須補足其 parent barrier 才能繼續或成功返回。
4. 記錄重試前後所有既存 files 的 bytes、SHA、device／inode。禁止 truncate、replace、
   overwrite 或藉由重建既存 entry 達成成功。注入 parent-directory substitution，確認
   barrier 使用被 pin 住且仍驗證通過的 directory，錯誤應傳出。
5. 至少一組 qualification 使用真實 bounded fixtures 與真實 chunk 重算；不可全部靠
   作者 cache 或 mocked `bounded_chunks`。保留 publication trace 及每個 fault point。

`link` 後 pathname 存在、bytes 正確，不代表先前 directory fsync 已完成。
上述 syscall ordering、process exit 與 injected EIO 結果，不得宣稱為實體斷電測試。
明列 Linux filesystem／mount 的 fsync 語義、exclusive cooperative writer、owner／mode、
ACL、既有 writable FD 與 writer quiescence 假設。不要把 flock 或 metadata 檢查當成
filesystem 強不可變性、kernel crash、remount 或跨主機 durability 證明。

## RR242-02：先驗 digest，重用同一份 capture

1. 在 output lock 內先 capture latest checkpoint，核對 externally supplied SHA-256，
   然後才讀取兩份 bounded fixtures 與執行 `bounded_chunks`。使用順序 spy 證明 lock
   已持有、latest 只 capture 一次，不能只比較總執行時間。
2. 分別使用格式正確但錯誤 digest、舊 prefix 的 stale digest。即使 fixtures 有效，
   也必須在 fixture read／`bounded_chunks` 開始前拒絕，且沒有 output publication。
3. 外部 digest 正確只通過 identity gate。之後仍須對 **同一份 captured bytes** 做
   strict UTF-8／duplicate-key／canonical encoding／exact bool-int-float／chain／
   complete-state／chunk semantic checks。對非法 snapshot 提供其正確 hash，仍須拒絕。
4. Capture 後替換 pathname 內容：不能重讀 pathname 的新 bytes 來挽救非法 capture；
   合法 capture 的 semantic input 也不能被後來 pathname bytes 取代。檢查 latest entry
   的位置／journal namespace 若改變會被拒絕，並說明 writer 假設與保證界線。
5. 確认正確 digest 的正常 resume、重複 resume、fresh equivalence 與所有既有 canonical／
   semantic negative cases 仍成立。不要以 digest-first 改動略過完整驗證。

## CR-02、保存與驗證

獨立確認以下四檔逐 byte 等同 parent `81374602`，再核對原 prompt 的三份 exact PDF
revision bytes／SHA、角色、頁碼、Table 2／4／7 區分及 verifier 行為：

- `src/pq_rbbc_cap_provenance_v2_42.py`
- `tests/test_pq_rbbc_cap_provenance_v2_42.py`
- `manifests/pq_rbbc_cap_unified_tree_provenance_v2_42.json`
- `docs/specs/PQ_RBBC_v2_42_PROVENANCE_ERRATUM_zh-TW.md`

重新核對 78 份 sealed predecessors 與 baseline
`973deee5b5603ee47ceadabd870004e214c81a96` 的 Git objects，以及 v2.33 sealed PDF。
歷史 checksum 的 mutable handoff 項仍使用各自歷史 object，v2.41 為 `1a1d576`；
不得改寫 sealed inventory 遷就新的 handoff。V2.41 reservation／approval 只核對
preservation evidence 的 exact identities，不讀出 private 原文、不改寫、不視為授權。

從 artifact note 重跑完整 targeted command 與 baseline：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

TMPDIR、logs、probes、qualification 皆放新的 `/tmp/pq-rbbc-v242-corrective-rereview-*`。
測試 total／passed／failures／errors／skipped 與 skip reasons 分開記錄。檢查 Git diff、
prohibited artifacts、各 inventory、portable evidence 與本次受審 source identities。
因 corrective manifest／source identity 改變，必須建立 fresh bounded fixture output；
不要重寫 `81374602` 的既存 journal 來規避 contract binding。

## 交付與禁止事項

輸出繁體中文 `AI_TECHNICAL_RE_REVIEW_zh-TW.md`、machine-readable `findings.json`、
commands／logs、probe observations 與 SHA-256 inventory，全部存入新的 external directory。
每項 finding 提供 ID、severity、exact commit／path／line、trigger、observed／expected、
可重現步驟及限制。RR242-01、RR242-02、CR-01、CR-02 分開判定，列出新 blocking findings。
即使沒有新 finding，也必須提供各項獨立驗證的實際觀察，且說明未測範圍。

不得修改 repository、amend、merge、push；不得建立 reservation、正式 review record、
launch candidate、production identity freeze，亦不得啟動 production、large replay 或 proving。
Tests 內既有 disposable synthetic fixtures 不得當成任何 operational authorization。
所有 production／security claims 維持 false。AI re-review 不等於具名獨立人員核准，
後續 reservation／human review／freeze／execution gates 均須另行授權，不在本次任務內。
