# GF partial issuance witness evaluator v0.1

日期：2026-09-14。Branch：`codex/threshold-gf-partial-issuance-v0-1`。
基準 commit：`d682b8b08892f663a81c4ef9d295b0c385354d0b`；tree：
`8b1527e87d3e61d986a25078ed5681717cdd7648`。

本輪實作一個取得完整 private witness 的 **局部 host evaluator**，將 frozen codecs、
pp／ctx／key record 自洽檢查、完整 M 的 I2 digest 計算、I4 holder binding 與 reference I5
串在同一次呼叫中。I3、設定 authentication、key-origin、backend qualification、native
constraints 與 proof 仍未實作。它沒有完整 relation accept、VerifyIssue 或 production 能力。

程式位於 `src/pq_threshold_candidates/gf/partial_issuance_v0_1/`；測試位於
`tests/threshold_candidates/gf/partial_issuance_v0_1/`。這是前一輪
[adapter 提案 §6](../trusted_adapter_contract_v0_1/CONTRACT_zh-TW.md) 指定的 T 自有 bounded
implementation；沒有代替 B owner 完成其 B-EVAL／B-VERIFY acceptance。

## 1. 精確 API 與輸入

```python
from pq_threshold_candidates.gf.partial_issuance_v0_1 import (
    ResearchPartialCheckStatus,
    evaluate_partial_issuance_research,
)

result = evaluate_partial_issuance_research(
    common_pp=pp_bytes,       # 489 bytes
    tpk_record=pk_bytes,      # 22590 bytes, complete canonical record
    statement=x_bytes,       # 251 bytes
    witness=w_bytes,         # 4324 bytes, contains private M/r/rho/k_hold/u
    purpose="research",
)
i5_matches = result.status("I5") is ResearchPartialCheckStatus.PASSED
# i5_matches 只回答本機 reference I5；result.full_relation_verified 永遠 False。
```

四個 inputs 均須為 exact immutable `bytes`，不接受 bytearray、memoryview、bytes subclass、
替代長度、未知 header／ABI 或 trailing bytes。Witness 中 M／CAP rho 的 nested canonical
grammar 也要通過；public key 使用既有 full-record parser，拒絕超出 q 的係數。
Runtime 不讀取 JSON、檔案路徑或外部 evidence，也沒有 caller-supplied verifier callback、
randomness sampler、secret-key 或 share input。

`purpose` 預設 `production`，會在 parser／witness／reference I5 前拋 `Unsupported`。
只有 exact string `research` 可以進入；未知或 alternate type 的 purpose 為 `ContractError`。
此 API 不修改 frozen ABI、crypto domains、common registry、原有 research binding checker，
也不處理 ticket／opening／M6 state。

## 2. 計算順序與各狀態的含義

所有 structural parse 成功才產生 diagnostic。下表中的「passed」只表示該列的局部比較。

| Check | 執行內容 | 成功時的狀態 |
| --- | --- | --- |
| P1_codecs | 完整 pp/key/statement/witness 與 nested M/rho 的 canonical shape | passed |
| P0_statement_pp | statement.pp 等於 SHA256(完整 489-byte common pp) | passed |
| P0_ticket_pp | witness.M.pp 等於同一完整 pp digest | passed |
| P0_trace_key | SHA256(完整 22590-byte pk record) 等於 pp.binding.tpk digest | passed |
| I1_statement_ctx | statement.ctx 等於 pp.binding.ctx | passed |
| I1_ticket_ctx | witness.M.ctx 等於同一 statement.ctx | passed |
| I2_digest | `SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32)`，含完整 3005-byte M header | computed_unjoined |
| I3 | 尚無 CAP／H_RBBC relation computation、r equality 或 beta join | open |
| I4 | `SHAKE256("PQ-RBBC/HOLD" || k_hold,32) == M.h` | passed |
| I5 | 同一 pk、statement.rid、M.ctx/sn/h/C 與 u128，重算並比較完整 c1–c4 | passed |

pp、key、ctx 任一比較失敗時，所有 binding comparisons 仍列出結果，但 I2／I4／I5 都標
`not_evaluated`；I5 call count 為零。這不表示連 public-key grammar 都未讀取，因為 canonical
parsing 先於局部 identity checks。

I2 沒有 public expected digest，也尚無 I3 消費端。計算 digest 本身不提供可失敗的 native
relation comparison，因此**永遠不能標成 I2 passed**。它的 d_M 只在函式內暫時存在，不放進
回傳值；後續要連入 I3，必須另行實作同一 digest 的實際 consumer 與 native join。

I4 mismatch 仍允許執行局部 I5，以便區分問題：只改 k_hold 時 I4 失敗、I5 可成立，因 I5
應使用 M 中的原始 h；只改 M.h 而不更新 C 時，I4 與 I5 都失敗。不能為了讓檢查互相配合
而把新算出的 holder hash 覆蓋 M.h。

I2／I4 的意外計算 exception 會標 `error` 並跳過後續計算；I5 exception 或非 exact bool
回傳值也標 `error`。回傳資料不包含 exception message。Structural errors 仍直接拋既有
`ContractError`；`failed`、`error`、`not_evaluated`、`computed_unjoined` 與 `open` 不互換。

## 3. 回傳值與尚未封閉的邊界

`ResearchPartialIssuanceEvaluation` 唯一儲存的 field 是固定順序的 checks/status tuple。
`failed_checks`、`errored_checks` 提供安全的 check labels；沒有 M、d_M、rid、sn、h、C、rho、
k_hold 或 u。Repr 也不包含 private inputs。

`bool(result)` 與 `bool(status)` 均拋 TypeError，必須明確比較狀態。沒有 `.ok` 或 `.accepted`
aggregate；`full_relation_verified`、`authentication_verified`、`production_qualified` 固定為
False。即使 caller 自行建構 diagnostic，它也不是可交回 verifier 的 credential。

固定 unresolved obligations 為：

- I2→I3 join、完整 CAP／H_RBBC I3。
- Configuration authentication、key-origin certification、backend qualification。
- Native constraints、proof verification。
- Issuer 的 identity/session authorization、witness freshness、threshold cryptography。

四個 API inputs 沒有 authenticated bundle、trusted pin 或原始 backend／origin evidence，
所以只能判斷**自洽**。Epoch／configuration digest／origin digest 格式正確但沒有可信來源時，
evaluator 不會驗其真實性；它也不取代先前含外部 research bundle pin 的
`check_key_pp_bindings_research`。未來 service 接合仍須依 adapter 提案的 S-AUTH → byte
bindings → T-ORIGIN → B-QUAL 順序建立可信 context。

GFR-01 的 u=0 跨 key 反例維持原狀：supplied key B 配 pp A，會在 P0_trace_key 失敗；若
caller 把 key、binding 及所有 pp pointers 一起改成相互一致的值，局部 I5 可以成立，但仍不會
得到 authentication 或完整 acceptance。不能把此局部 evaluator 當成可信 key selection。

## 4. 驗證覆蓋與限制

新增 27 項 tests 使用 deterministic reference keys、真實 reference encryption、既有 codec
fixture 與 canonical rho。Fixture 的 r／beta 並非完整 I3 正例，測試從未把它命名為完整
honest issuance 或 proof。

| 測試範圍 | 已觀察到的結果 |
| --- | --- |
| Normal reference I4/I5、不同 holder/rid/sn、合法 zero/all-one u | 已實作局部檢查成立；I2 computed_unjoined，I3 OPEN |
| Wrong pp／capsule digest／ctx／key record；GFR-01 | 對應 binding 失敗，I2／I4／I5 未執行 |
| 完整 M hash 與 pp header mutation | Spy 核對 exact preimage／digest；pp 改變後 digest 改變，未宣稱測過簽章拒絕 |
| rid/sn/h/k_hold/u 變異；各 c1–c4 的首尾 byte | I4／I5 的對應局部 mismatch 被捕捉 |
| Codec 合法的 beta/r/rho mutation | 不改變已執行檢查；I3 仍 OPEN，CAP execution call count=0 |
| sid／opaque setup metadata 改變、完整自洽 key/pp 替換 | 明確展示 authentication／origin／issuer authorization 沒有被檢查 |
| 同一輸入重複呼叫、u extreme values | 不呼叫 randomness sampler；沒有 freshness 或 replay 拒絕宣稱 |
| Wrong purpose／mutable bytes／nested ABI／CAP padding | 前置拒絕，無 reference I5 呼叫 |
| I2／I4／I5 fault injection、I5 回傳 1/0/None/string | ERROR 或跳過；不把 truthy／非 bool 值當成成功，不帶 exception 原文 |

這些是 host／reference tests，不是 native row replay、formal proof、upstream KAT 或外部獨立
review。本模組無持久狀態、票證消耗或多輪 transcript，故本輪不宣稱 concurrency、crash
recovery、durability、AKE 或 opening 性質。Variable-time Python reference 與 non-threshold
profile 的限制仍在。

## 5. 重跑與交付

在本分支 repository root 執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates/gf/partial_issuance_v0_1 -t tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/trusted_adapter_contract_v0_1/check_contract_v0_1.py
git diff --check
```

| 本輪 test run | Passed | Failed/errors | Skipped | Elapsed |
| --- | ---: | ---: | ---: | ---: |
| 新 partial evaluator tests | 27 | 0 | 0 | 4.395 s |
| Threshold targeted（含新增 tests） | 117 | 0 | 0 | 17.416 s |
| Full regression | 793 | 0 | 12 | 760.788 s |

Full regression 共 805 項；12 個 skips 均因對應 optional external artifacts
未安裝，沒有為消除 skips 下載資料。Full run 開始前與結束後，四份新增 source/test
的 bytes／SHA-256 均相同。Frozen adapter document checker 的 3 positives、30 mutations
與 5 malformed JSON report 和前輪 digest 相同；這不等於執行 TA01–TA16 cryptographic acceptance。

精確 source revisions／bytes／SHA-256 見 [source_index_v0_1.json](source_index_v0_1.json)。
測試計數、elapsed、log identities、skips 與本輪 claims 見
[validation_summary_v0_1.json](validation_summary_v0_1.json)。Raw logs 保留 repository 外；
沒有提交 witness bytes、keys、PDF、下載資料、大型 artifacts、pickle、cache 或 assignments。

Root methodology、experiments、RESEARCH_STATUS 由 integration owner 管理；本文件提供
設計理由、執行範圍與受限 claim，未改寫 root canonical 或其他工作線檔案。I3／native
relation／proof 的後續實作仍需對應 owner 交付；本輪沒有擴大其 acceptance 狀態。
