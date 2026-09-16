# I3 private CAP candidate hash consumer：同作者技術複核 v0.1

日期：2026-09-14。Branch：`codex/threshold-gf-i3-hash-review-v0-1`。
複核 target commit：`2289fb2e5eee25ed12574f70b7f1831b3fa682a0`；tree：
`f8e675b142d9c0edce564b80878e1d124f57bbab`。

本輪接續 [I3 hash consumer 實作](../i3_hash_join_v0_1/IMPLEMENTATION_zh-TW.md)，複核
private CAP candidate grammar、完整 M digest 的傳遞、H_RBBC framing／padding／lane
packing、錯誤停止順序與受限回傳狀態。本次範圍不包含 CAP(rho)、derived mask、native
constraints 或 proof。

## 1. 方法與共用依賴

[check_review_v0_1.py](check_review_v0_1.py) 另行組裝 5,391-byte legacy18 candidate。
其 grammar predicate 使用固定 prefix、correction length 和欄位 padding masks，不呼叫
runtime serializer／parser 產生預期答案。對被測 `_parse_candidate` 接受的封包，另以
raw slices／`int.from_bytes` 核對 salt、h2、alpha、全部 17 組 delta_p／delta_mhat；
不只檢查 parser 是否拋例外。

GF pp／X／M／W 使用先前複核的 raw-byte builder 與另一套 GF polynomial oracle，以新
labels 生成不同輸入。Builder 依 frozen JSON offsets 組裝，不沿用本輪 target tests 的
fixture 或 runtime codec encoders。Public matrices 是合法編碼的合成輸入，沒有 KeyGen
或 origin 認證；CAP candidate 也不是執行 CAP(rho) 得到的正例。

第二套 hash 路徑自行串接 transcript 與 outer frame，將完整 frame 視為 little-endian
integer，直接放置 `10*1` padding bits，以 772-bit blocks／193-bit lanes 拆開，逐 block
absorb，再取前 576 output bits。它沒有呼叫 runtime 的 `encode_transcript`、
`framed_rate_blocks`、`evaluate_sponge` 或 `hash_request_binding` 來產生預期 hash。

**Anemoi parameters 和八個 lanes 的 permutation 仍共用既有 implementation。** 本輪沒有
另寫或獨立證明 permutation、field arithmetic 或 parameter derivation。這是同作者使用
不同 framing／packing 計算的技術複核，不是外部 independent review、upstream KAT 或
密碼學安全驗證。精確共用來源、revisions、bytes／SHA-256 和引用位置列於
[source_index_v0_1.json](source_index_v0_1.json)。

## 2. Candidate grammar 與前置拒絕

Canonical candidate 必須包含 exact 54-byte magic／version／profile prefix、固定
5,234-byte correction length，以及兩個 193-bit salt、h2／alpha／17 個 delta_mhat 的
386-bit padding。Delta_p 的 2,048 bits 全部為數值位元；沒有額外 padding 或非零要求。

實驗對全部 43,128 個 bit 逐一翻轉：與 target parser 比較接受／拒絕，接受時再核對
所有 decoded fields。另測全零／最大 numeric fields，以及短、長、mutable、memoryview、
bytes subclass 和 None。這些檢查只回答 canonical grammar，不回答 CAP admissibility。

所有 grammar-invalid 單 bit inputs 亦送入完整 API，確認在 partial evaluator 和
H_RBBC 前拋 `ContractError`。Default／explicit production，以及 alternate purpose types，
使用不可解析的 poison inputs，確認在 profile check／parser 前拒絕。

## 3. 真實 hash 與停止順序

真實 hash 案例涵蓋不同 candidate、更新 pp pointers 後的完整 M，以及刻意用 u32 field
lengths 算出的錯誤 beta。正確 transcript 的兩個 field lengths 都是 **u64le**。
執行 target 時，逐次比對其傳入 permutation 的完整八-lane state 和第二套計算的 state，
同時核對 H_RBBC 實際接收完整 M 的 d_M 及同一 captured candidate。

控制流程另枚舉七個 boolean 條件的 128 種組合：binding mismatch、salt mismatch、
partial I5 ERROR、第二次 digest ERROR、hash 非 canonical 回傳、beta mismatch 和 holder
mismatch。預期停止順序從各 predicate 和失敗優先順序推導；比對實際 candidate parse、
partial evaluator、兩次 I2 和 H_RBBC 呼叫，以及所有回傳 statuses。

這 128 個組合只檢查資料流與狀態。在確認 d_M／candidate 與 baseline 完全相同後，才
重用第二套計算已產生的 image，沒有把 patched 呼叫另算為真實 Anemoi execution。
所有 diagnostics 都檢查固定 labels、safe repr、bool 拒絕、原有 partial 狀態、固定
False 的完整性屬性，以及 CAP origin／rho execution／mask derivation 的 OPEN 狀態。
CAP execution 的實際呼叫數須為 0。

## 4. 結果與 findings

本次範圍內**沒有新增可重現實作偏差**；`new_findings` 為空，沒有修改 runtime 或
tests。各階段結果如下，不能把 grammar 接受數解讀為 CAP／I3 正例數：

| 階段 | 本輪結果 |
| --- | --- |
| 43,128 個單 bit candidate mutations | 42,536 grammar 接受、592 拒絕；decoded fields 與另一套解析相同 |
| 額外 numeric boundary／type-length cases | 2 個合法 boundary 接受、6 個異常 input 拒絕 |
| 完整 API 的 malformed-candidate 前置拒絕 | 592 個均在 partial crypto／H_RBBC 前拒絕 |
| Purpose 前置拒絕 | 4 個均在 profiles／parser 前拒絕 |
| 真實 hash differential | 3 個 candidate 方程相等；1 個 u32 transcript 所造的 beta 被拒絕 |
| Permutation input-state 比較 | 四次 target execution 各比對 58, 58, 58, 58 個 state，全部相同 |
| 128 種 flow combinations | 2 個 matched_unverified_cap、2 個 beta failed、124 個 beta not_evaluated |
| Grammar／status／call-order disagreement | 均為 0 |

上述單 bit corpus 在 parser 階段與完整 API 前置拒絕階段重用，不另外宣稱是不同的
獨立輸入 corpus。所有回傳結果的 CAP execution／derived mask 仍為 OPEN，完整 I3、
authentication、proof／production qualification 沒有被升格；CAP executor touch count=0。
Review 程式耗時 599.295 s，包含反覆執行完整 parser 的 profile
derivation；這不是 CAP tree／native replay benchmark，也不作 production 效能外推。

| Test run | Passed | Failed | Errors | Skipped | Elapsed |
| --- | ---: | ---: | ---: | ---: | ---: |
| 本輪 threshold targeted | 142 | 0 | 0 | 0 | 49.059 s |
| 前輪 full regression；**本輪未重跑** | 818 | 0 | 0 | 12 | 791.507 s |

前輪 full 共 830 項，12 skips 均因對應 optional external artifacts 未安裝。本輪維持
全部 `src/`／`tests/` bytes 相同，重跑相關 targeted suite，並重新核對前輪 full log 的
size／digest；沒有把歷史 full run 計成本輪重跑。


## 5. 來源、限制與下一個 gate

重新核對了 19 份 canonical／研究政策文件、5 份附件、7 份 target 交付來源、13 份
repository 引用、3 份已提交的其他工作線快照及 2 份共用 review builder／oracle。
前輪 full regression log 的 bytes／SHA-256 亦相符。附件完整名稱、revision attribution、
bytes／SHA-256 與原論文引用位置仍保存在 [原始來源 inventory](../../source_inventory_v1.json)。
本次沒有新增 paper-verified 或 publisher byte-equivalence 宣稱；附件／handoff 是研究
資料，不是執行授權。

完整 I3 仍需要對同一 captured rho 取得經實際計算或合格驗證的 CAP commitment 與
derived mask，再檢查 witness r equality 並接入 H_RBBC。Caller 自報 candidate、調整
r／beta、parser success 或局部 hash match 都不能替代這段關係。本輪沒有重評 B 活動
分支的最新 readiness；B 依賴仍按 target 實作已核對的 exact revisions 歸屬。

Runtime、tests、frozen ABI、root canonical 文件和其他 owner 工作樹均保持原樣。本輪
只新增 literature review 程式／紀錄／索引／摘要與 GF 導覽連結。設計理由與結果由本文件
供 integration owner 整合至 methodology、experiments、RESEARCH_STATUS。
沒有 PDF、下載資料、raw logs、private vectors、cache、assignments 或大型 artifacts
加入 Git，也沒有 merge／push。

## 6. 重跑

```bash
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/i3_hash_review_v0_1/check_review_v0_1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
git diff --check
```

Review 程式輸出只有 aggregate counts 與公開 profile identity；不輸出 candidate、M、
d_M、mask、sponge states 或其他 private values。若保存 report／logs，路徑須在 repository
外。程式在 Python optimization 下立即拒絕，避免 assertions 被移除後仍產生成功報告。
精確命令、結果、elapsed、原始 log identities 與 claims 見
[validation_summary_v0_1.json](validation_summary_v0_1.json)。
