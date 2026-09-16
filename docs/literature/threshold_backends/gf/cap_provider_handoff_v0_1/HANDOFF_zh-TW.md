# GF legacy18 CAP provider 接合交付 v0.1

日期：2026-09-14。T 基線 `417ee834ffb7fa26740b22cb43716099b0fed635`；
B 唯讀來源固定於 `c1c2b5d2690643fc136e4c39a867e4376cdb9a97`。
本文件細化 [trusted adapter 提案的 J03–J05](../trusted_adapter_contract_v0_1/CONTRACT_zh-TW.md)，
是 **T 提出的交付要求，B／system owner acceptance 尚未取得**，不是新的 canonical contract。

本輪完成來源核對、相依缺口檢查及未執行的 provider 驗收案例。
沒有新增 CAP executor、derived-mask verifier 或 full I3 成功路徑。
[既有 candidate consumer](../i3_hash_join_v0_1/IMPLEMENTATION_zh-TW.md) 的兩項 CAP 檢查仍為 OPEN。

## 1. B 新 checkpoint 的適用範圍

| 比較項目 | Frozen GF 所需 legacy18 | B `c1c2b5d` bounded adapter |
| --- | --- | --- |
| CAP profile SHA-256 | `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38` | `520980f7518de0c8a22e9fcb66f3d3af1eb4ef50c2df9136b6df873d9f524356` |
| Trees／leaves | 18／40,960 | 2／8 |
| Extension degrees | 13、12 | 3 |
| Security bits 欄位 | 192 | 0（INSECURE-TEST-ONLY） |
| Canonical rho bytes | 1,036 | 236 |
| Canonical commitment bytes | 5,391 | 511 |
| Mask／witness bits | 576／2,048 | 576／2,048 |
| Production executor | 尚無可接合交付 | public API 立即 raise unavailable |

以上 widths 是由固定 profile／serializer 計算的 **格式長度**，不是新的 CAP 執行觀測。
`security_bits=192` 或 library `secure_profile=True` 也不構成安全性證明。

Finding **CP-F01（相容性缺口）**：相同 mask／witness 寬度不足以接合。
B 新增的 4+4 bounded native adapter 確實有自己的 rows／relocation evidence，
但 profile、roots 數及 commitment 長度不同。不得截短 GF rho、補長 bounded commitment，
或改寫 fingerprint 後當作 legacy18 輸出。

Finding **CP-F02（provider 缺口）**：B 的 `execute_production` 與
`execute_production_child` 在函式進入後直接 raise；native helpers 只允許 exact bounded profile。
本輪以固定來源的 AST 核對 public refusal，不 import 或執行 B 工作樹。
B manifest 也保留 production adapter／mixed degree-12/13 qualification 為 false。
這是該 checkpoint 明示的限制，沒有發現其文件與原始碼互相衝突。

B 的測試摘要屬其歷史證據，本輪沒有重跑 B 的 native streams，也沒有啟動新的 private-spool 工作。
舊 large monolithic `allow_large=True` 入口不提供這份 provider 交付；本輪不啟動大型 CAP。

## 2. B 必須交付的最小能力

以下是內部 semantic operations，**尚未註冊新的 Python API 或 wire codec**。
機器可讀要求及案例見 [requirements_v0_1.json](requirements_v0_1.json)。

1. **精確版本與能力**：交付固定 commit、implementation／profile identities、可用入口與
   execution 範圍。入口能消費完整 18-tree rho，並有實際運算與驗收證據；只提供 manifest
   欄位、receipt digest 或 `available=True` 不滿足此要求。原有 production resource／review／
   execution prerequisites 仍依 B 的 canonical gates；一般「下一步」不能替代它們。
2. **同一 captured input**：T strict-decode 同一 immutable W，取 `W[3128:4164]` 的完整
   1,036-byte rho。Identity、parse、CAP execution 都消費這份值，不重開 pathname；
   保留 18 個 root pairs、兩個 salts 及 field padding。Provider 不得自行截短或重新抽樣 rho。
3. **同一 execution 的 private outputs**：由該次 CAP computation 直接取得 canonical
   `c_r: bytes[5391]` 及其 `derived_mask`。接合端將 exact int、範圍 `0 <= mask < 2^576`
   的實際 derived mask 轉成 72-byte little-endian；拒絕 bool、負值及超寬值。
   這是內部值轉換，不新增 caller 可提交的 output record／receipt。
4. **來源綁定**：executor 實際輸出與同一 rho 的運算 trace／reference 核對；兩個相同 salt
   但不同 roots 的反例須選擇經實算確認 outputs 不同的 fixture；不主張 CAP 映射必為單射。
   Commitment parser、salt equality、caller 自報 rho digest
   或 caller 建構的 `CAPCommitment`／Protocol object 都不能證明來源。
5. **可核查交付**：分別提供 host execution 與 native constraint 的來源、命令、exact input／
   output identities、passed／failed／skipped 及未解缺口。私密值保留於明確 provision 的外部
   路徑；Git 只存允許的摘要與 digest。提供機器證據不能自動取得 owner acceptance。

Provider 若只實作 CAP，T 以既有 H_RBBC 消費其輸出；若 B child 同時算 H_RBBC，
它還必須消費 **T 由完整 3,005-byte M 算出的同一 d_M**，不能沿用 NIED 的 message 定義。
T 應獨立重算 host H，比較同一 private output；native equality obligations 另外驗收。

## 3. Provider 到位後的 T 接線順序

未來的研究入口只接 common pp、完整 tpk record、X、W，及用途選擇。
Provider 由已核對的實作固定選擇；request 不得注入 executor、mask、commitment、receipt、
`verified` 或 `allow_large`。此 ABI 的 production 預設仍須在 private parse／CAP 前拒絕。

```text
purpose / supported implementation profiles
  -> strict immutable pp489 / key22590 / X251 / W4324
  -> full pp / key / ctx bindings
  -> d_M = SHAKE256("PQ-RBBC/TICKET" || entire M3005, 32)
  -> execute pinned CAP with entire captured rho1036
  -> same execution c_r5391 + actual derived mask
  -> strict c_r + profile + salt checks; W.r72 == derived_mask.to_bytes(72, "little")
  -> H_RBBC(d_M, same c_r), exactly 72 bytes
  -> X.beta72 == W.r72 XOR H_RBBC result
```

Binding failure／unsupported profile 必須使 CAP touch count 為零。
Provider exception、非 canonical output、不同來源的 outputs 或 derived-mask mismatch
必須使後續 H touch count 為零，不能退回 candidate consumer 的 match 狀態。
Caller 自行修正 beta 也不能消除 r 的不等式。

現有 candidate result 型別刻意禁止 CAP 項目離開 OPEN；接線時應使用另行審查的
host diagnostic 型別，不修改既有型別來接收 caller 成功旗標。即使將來 host I3
算式全部成立，也須與 native relation、authentication、key origin、PQ-SE proof 與
Production-closed 分開記錄。GF reference 仍是 non-threshold full-key research profile。

## 4. Native join 與 private partition 的獨立交付

| Obligation | B 必須展示的 ordinary constraints |
| --- | --- |
| J03 | I2 使用完整 M（含 ABI／pp header），同一 256-bit d_M 進 H_RBBC |
| J04 | 完整 rho 進 CAP；CAP 產出的 576-bit derived mask 與 W.r 的同一 bit vector 相等 |
| J05 | 同一次 CAP 的 43,128-bit encoded c_r 進 H_RBBC；同一 r 與 H output XOR 等於 public beta |

Host bytes equality、stage receipt、port digest、private snapshot identity 與 ordinary native
constraint replay 是不同證據。B 須逐項列出 producer／consumer wires、equality rows
及只改一側值的 mutation 拒絕；本輪未替 B 配置 GF relation wires。

X 仍為 251 bytes、W 為 4,324 bytes、common pp 為 489 bytes。rho、r、c_r、d_M、M、
CAP state 不加入 public statement、per-ticket pp 或公開 proof header；公開驗證不接 W。
私密 internal output 的 digest 也不自動成為可公開的逐票識別資料。

## 5. 驗收與下一步

`requirements_v0_1.json` 列出 20 個待執行案例，含真實 legacy18 正例、同 salt 換 roots、
偽造 commitment、換 r 並修 beta、跨 invocation 拼接、early refusal、private output 隔離，
以及 J03–J05 的 native mutations。**這 20 個案例目前全部 not_run**；本輪 checker 通過
不能填成 provider tests passed。

可重跑的相依檢查：

```bash
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/cap_provider_handoff_v0_1/check_handoff_v0_1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
git diff --check
```

Checker 需本機 Git object database 包含所列 exact B commit；缺少就明確失敗，不改讀移動的
branch／worktree，也不自動下載。它核對來源、格式與拒絕分支；exit 0 的意思是
**本 checkpoint 的相依缺口與文件一致**，輸出仍為 `dependency_open`／provider unavailable。
它不是通用 launch gate，不能以修改 JSON 布林值取得資格或執行授權。

驗證結果及歷史 baseline 區別見 [validation_summary_v0_1.json](validation_summary_v0_1.json)。
來源的完整檔名、revision、bytes、SHA-256、引用位置見 [source_index_v0_1.json](source_index_v0_1.json)。
五份附件沿用已固定的 original inventory，另重新核對 identity；沒有新增 paper-verified
或 publisher byte-equivalence claim，附件內容仍只作研究輸入。

下一個 runtime 步驟是 **B 交付匹配上述 profile 與同一 rho 的真實 CAP outputs 後，T 實作
內部 provider 接線與 derived-mask equality**。目前不具備該相依項目；不先引入可偽造的
provider 結果介面。設計理由、實驗與 claim boundary 先保存在本 T literature 交付，
供 integration owner 同步 root canonical documents；沒有修改 B、system 或其他 worktree。
