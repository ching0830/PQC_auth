# TB2 TH-GF checkpoint：實際尺寸的 non-threshold reference

日期：2026-09-13。使用者同意開始 TB1 之後的下一步，本輪選定 TH-GF 並完成局部研究
profile、full-key 單機 encryption/decryption、witness-bearing I5 evaluator 與驗證。
選擇理由見 [REFERENCE_PROFILE](REFERENCE_PROFILE_zh-TW.md)；這不是三候選的最終選型。

## Git 與權責

- Canonical main：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`，啟動時未前進。
- 直接 base／TB1：`6bb4dab80fe577041b7eb517be11f0e2ef2e9c9c`，tree `727bcbcbd242ffe15047adf92ecab18071877bbb`。
- Branch：`codex/threshold-gf-tb2-reference`；使用獨立 worktree。
- 本次僅新增 `src/pq_threshold_candidates/gf/`、`tests/threshold_candidates/gf/` 與本目錄。
- 既有 TB1/source-audit 的 19 個檔案、canonical 文件、opening、reference KDF、B 工作線及其他 worktree 未修改。

Result commit/tree 由交付時的 Git 回報；本文件隨該 commit 保存，避免自我引用 hash。
沒有 merge、push、production launch、大型 proving 或 artifact replay。PDF、抽出文字、
渲染圖、raw test logs、秘密 key／u／plaintext／seed 都不加入 Git。
測試 source 中明示的公開 deterministic fixture 定義只用於 regression；公開 vectors 檔僅含 digests。

## 完成範圍與狀態

Profile ID：`gf-hybrid2-pompeii-d4-shake256-otp-ref-v1`。
Descriptor fingerprint：`3077ddb7e9f90c2a551c0fccff8719655b5e852394aa4e9326c9a7801225a9b7`
（canonical JSON 的 SHA-256，與 pretty-printed JSON file digest 是不同 identity）。

| 對象 | 本輪狀態 | 限制 |
| --- | --- | --- |
| 底層參數、CBD1、centered representation、rounding、Fig. 14 equations | 原文對照＋Implemented／Tested | n=256,d=4 實際尺寸；未宣稱標準安全等級或極小 failure bound |
| Hybrid2 SHAKE256／OTP 局部 profile | Defined／Instantiated／Implemented／Tested | hash domains、g=32、DEM 是本案選擇；完整 paper/security qualification OPEN |
| KeyGen／Enc／Dec | PASS，full-key non-threshold reference | variable-time Python、local full secret key；沒有 threshold cryptography |
| I5 reference evaluator／128-byte u descriptor | PASS，候選內部 | 帶 witness；I1–I4 constraints、B ABI、完整 Pi_issue OPEN |
| Strict candidate record | PASS | 與 TB1 envelope 分離；common registry 未註冊新 profile |
| DKG／share validity／interactive opening | OPEN，未實作 | 無 distributed execution 或數據 |
| T1–T4／QROM／independent review | OPEN | 沒有 Proof-closed／Production-closed 宣告 |
| TH-UT／TH-NIED | 保持 TB1 OPEN | 本輪未實作 |

## 驗證與重現

環境：Python 3.12.9、Linux x86_64、stdlib。沒有新增套件或外部 crypto library。
Command cwd 為本 branch repository root：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pq_threshold_candidates.gf --samples 8
git diff --check
```

| 檢查 | Passed | Failed/errors | Skipped | Elapsed |
| --- | --- | --- | --- | --- |
| Threshold targeted（TB1 28＋GF 26） | 54 | 0 | 0 | 4.932 s |
| Full regression（742 total） | 730 | 0 | 12 | 751.137 s |

新測試包括：exact rational rounding 的正負 ties 與超過浮點精度的整數、negacyclic sign、
centering endpoints、獨立 CBD/rejection/XOF stream、完整 KeyGen 方程與 Pompeii encryption
的不同係數演算、獨立 bit packing／domain framing、四個 ciphertext components 的 mutation、
reencryption 必要性、c4/c3/DEM 呼叫順序、AD 每個欄位、錯 key、錯 witness／relation inputs、
帶有效 c3 但內外 serial 不同的 ciphertext、record header 各 byte 的 mutation、mod-q range、
truncation／trailing／type／sample bounds，以及 common production/share 拒絕。

初次 23 項 GF 算術／reference 測試與後續 54 項 targeted 均無失敗；最終 targeted 額外包含
CLI 與不輸出秘密資料的 report schema 檢查。Full suite 包含這 26 項新增測試。
12 項 skip 均因缺少指定的 v2.13–v2.25 外部 assignments／cache／replay artifacts；沒有跳過新 GF 測試，
沒有把 skip 計為 pass。完整 skip reasons 保留在 evidence summary。
回歸 digests 是本地生成，獨立公式對照是另寫的 test oracle；沒有冒稱外部實作的 KAT。

重核 exact `2021-096.pdf` 的 695,683 bytes／SHA-256，19 份既有 audited repository
identities 及 19 份 TB1/source-audit 檔案均一致。論文完整名稱、revision 歸屬限制與引用位置
見 [profile 來源對照](REFERENCE_PROFILE_zh-TW.md)。沒有將 handoff 的公式直接標為 paper-verified。

## Reference 數據與 estimates

測量摘要由 [tb2_evidence_summary_v1.json](tb2_evidence_summary_v1.json) 綁定本輪 source
digests、descriptor、command、環境與結果。測試 log／原始 measurement JSON 在 repository
外保存；tracked 文件只含 digest 與必要摘要，不是一份 proof 或 portable cryptographic seal。

| 欄位 | Bytes | 類型 |
| --- | --- | --- |
| Public-key payload | 22528 | measured_reference |
| Public-key record | 22590 | measured_reference |
| Ciphertext payload | 2848 | measured_reference |
| Ciphertext record | 2910 | measured_reference |
| Ticket 已知部分（80+2848+11644） | 14572 | estimated；sigma provisional |
| Ticket 完整大小 | null | extra/framing 未整合 |

完整 regression 結束後，另以新 keypair／fresh witnesses 執行 8 次：8 次解密及 8 次 relation evaluator 全成功。
KeyGen 128.644 ms；8 筆的 lower median（排序第 4 筆）為 encryption 61.347 ms、
decryption 93.504 ms、relation evaluator 61.536 ms。
此次測量未與本輪 targeted／full tests 重疊；環境仍非受控效能實驗。

這些是本機 Python 單次測量，沒有建立效能分佈或 failure probability bound，不能與原文
其他 profile 的 distributed runtime 作直接比較。Measured threshold 與 satellite online
observation 均為 null；加密關係 evaluator 的時間也不是 issuance ZK proving／verification 時間。

提交前 `git diff --check`／staged diff、變更範圍、JSON identities 與文件連結均已檢查。

## 剩餘義務與下一關

[I5_INTERFACE_REQUEST](I5_INTERFACE_REQUEST_zh-TW.md) 提供三個具體 CR：新 reference
profile 的 common 註冊、B 的 witness／M／I5 relation ABI，以及正式 opening adapter。
本輪未改變這些共用契約，也未把 root canonical status 升級。
Integration owner 可將本輪選擇理由登錄 methodology、命令／結果登錄 experiments、受限
reference 狀態登錄 RESEARCH_STATUS；本文件提供其可審查輸入。

下一關應先獨立審查此 profile 的公式／編碼／外部向量與安全假設，處置 CR 並決定是否進入
TH-GF 的多輪設計或先對另一候選建立 reference。T1 的 failure/bad-key、T2 QPT model、
T3 uniqueness、T4 robust shares 及 OA DKG／授權 session/replay 仍 OPEN。
本輪成功不授予 production launch 或大型 proving／replay 的執行資格。
