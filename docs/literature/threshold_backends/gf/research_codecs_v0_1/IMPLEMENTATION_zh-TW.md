# GF strict research codecs 與 key／pp 一致性檢查 v0.1

日期：2026-09-14。Branch：`codex/threshold-gf-research-codecs-v0-1`。
基準 commit：`1eb44e912cee6f69c77b859cebae748fd12131c1`，tree：
`779f2ea70398c4c9fcac97784753dc0c7bbad4c9`。

**已實作／測試**：T 自有 namespace 的 5 種 strict research codecs、legacy CAP rho canonical
encoding、完整公鑰 record identity，以及以外部 research bundle pin 為前提的 key/pp/M/statement
一致性檢查。**未實作**：設定 authentication、key-origin certification、B proof、完整 I1–I5
constraints、trusted VerifyTicket/opening 或 threshold cryptography。

程式位於 `src/pq_threshold_candidates/gf/research_abi_v0_1/`，測試位於
`tests/threshold_candidates/gf/research_abi_v0_1/`。本輪保留
[frozen ABI](../abi_v0_1/SPEC_zh-TW.md)、crypto profile 與歷史 evidence；沒有把規格檔內的
歷史 `implemented=false` flags 回寫成新的 ABI fingerprint。

## 1. Codec 行為與編碼

| Python type | Bytes | 本輪處理 |
| --- | ---: | --- |
| `ResearchTraceBinding` | 315 | 固定 profile、OA role=5、research purpose=1；nonzero identities，epoch=u64le |
| `ResearchCommonPP` | 489 | 巢狀 binding、backend/relation digests、固定 CAP/H_RBBC profiles |
| `ResearchTicketM` | 3005 | ABI/pp header 及 ctx/sn/h/raw C；`d_M` hash 完整 M |
| `ResearchIssueStatement` | 251 | pp/ctx/sid/rid/beta，沒有 M/u/k_hold 等私密欄位 |
| `ResearchIssueWitness` | 4324 | 巢狀 M、r72/rho1036/k_hold32/u128；repr 不列出私密內容 |

ABI fingerprint 固定為
`97e97589fdcb293101e866a3233b38e1f48c9bdbe5ad9ddc1daabe5f2b410158`。
Runtime 不讀取 JSON 決定 grammar；tests 以凍結 JSON 的每個 offset／literal／nested size
另行對照。Unknown magic/version/ABI/profile、固定 role/purpose 錯誤、truncation、trailing bytes、
零 identity、不正確長度、bool 冒充 epoch、bytearray/memoryview/bytes subclass 均拒絕。
Builder 與 decoder 同樣驗證；不自動剝除 candidate record 或截斷／補零。

M 的 raw C 2848 bytes 可轉回 TB2 `ReferenceCiphertext`；u128 可轉回 `ReferenceWitness`。
這些 adapters 只做固定格式對應。Zero/all-one u 均是合法 codec 輸入，不套用 NIED error
weight constraint；sn=0 也不在此格式層排除。AD 僅為 ctx||sn||h，仍是 80 bytes；M header
不偷偷加入 TB2 的 hash domains 或 AD。

### Rho 與 r／beta

Legacy CAP rho 的 grammar 延用 pinned serializer／B preflight：

```text
"PQRBBC-CAP-RANDOM-V1" || CAP fingerprint 的 64-byte lowercase ASCII hex
|| salt[0]:25 || salt[1]:25 || tree_count:u16le(18)
|| 18 * (left_root:25 || right_root:25)
```

共 1036 bytes；38 個 GF(2^193) elements 的最高 7 bits 必須為零。本輪只檢查 encoding，
不展開 CAP trees、生成 commitment、驗 I3 或啟動 proving。Pinned B 的 r/beta 是完整
576-bit XOR 向量，即 72 raw bytes，所有 bit patterns 都有 canonical 表示；它們不是
38 個 GF(2^193) elements，也不適用 rho 的 padding-bit 檢查。

前一輪 document checker 的 synthetic witness 把 rho 刻意視為 opaque；其 digest 仍是
歷史格式錨點。新 runtime decoder **會拒絕那個 synthetic witness**，因它沒有有效 CAP header。
測試對照其原 digest 後明確驗拒絕；其他四個 frozen structural vectors 可 round-trip。
新的有效 rho 測試由既有 local CAP serializer 產生，未把私密 witness bytes 加入 Git。

## 2. Key／pp checker 的精確界線

`check_key_pp_bindings_research` 只收已 capture 的 immutable bytes，沒有檔案路徑、network、
pickle、可重開檔案的 callback，亦不呼叫 encryption／signature／proof／opening backend。
`purpose` 預設 `production` 並立即拋 `Unsupported`；只有精確 `purpose="research"` 能檢查
一致性。研究 opt-in 不能讓 production 入口成功。

研究呼叫範例（變數皆由呼叫者準備；沒有自製證書或信任判定）：

```python
from pq_threshold_candidates.gf.research_abi_v0_1 import (
    ResearchTicketM, check_key_pp_bindings_research,
)

m = ResearchTicketM.decode(m_bytes)
match = check_key_pp_bindings_research(
    purpose="research",
    expected_bundle_sha256=externally_selected_research_pin,
    initialization_bundle=canonical_public_bundle_bytes,
    common_pp=common_pp_bytes,
    tpk_record=canonical_gf_public_key_record,
    key_origin_evidence=key_origin_input_bytes,
    issue_backend_pp=backend_pp_input_bytes,
    gf_full_relation_manifest=relation_input_bytes,
    statement=statement_bytes,
    ticket_m=m_bytes,
)
```

`initialization_bundle` 是 canonical **public SystemInitializationBundle**，不是已驗證的
AuthenticatedSystemInitialization wrapper。`expected_bundle_sha256` 必須另由呼叫者指定，
本 API 不自行信任 bundle 自報的 digest；但研究 caller 也能自選一致的假資料／pin。
因此成功只代表下列 bytes equality，不能證明 pin 或輸入具有可信來源：

1. 先比對 bundle 的 SHA-256 與外部 pin，通過才 decode；bundle 格式仍須 canonical。
2. 完整 489-byte pp digest 對上 bundle.common_parameters_digest，不接受 315-byte capsule digest。
3. Binding 的 configuration hash、ctx、epoch、OA/issuer key IDs 及 issuer digest 對上同一 bundle。
4. 公鑰通過完整 TB2 record／係數 canonical parser；其 **22590-byte record SHA-256** 同時
   對上 binding 與 bundle.OPENING_ENCRYPTION 的 digest，不能用 body、seed 或 key ID 代替。
5. 三份 opaque inputs 的 exact SHA-256 對上 pp/binding；每份為 1..1048576 bytes。
   這不是 certificate／backend／relation manifest 的 schema、簽章或 qualification 驗證。
6. statement 與 M 的 pp digest 都等於同一完整 pp，ctx 都等於同一 bundle.ctx。

Bundle input 限 1..65536 bytes，其 canonical parser 實際另限制固定系統 layout；其他 packets
有固定 exact 長度。外部 bytes 不會被 JSON／pickle deserialize 或執行。

回傳 `ResearchBindingMatch` 只含三個 public identity digests；其 `authentication_verified`
與 `production_qualified` 永遠 False。`bool(match)` 拋 TypeError，避免直接當作接受 boolean。
Mismatch 以 `ResearchBindingMismatch.code` 報欄位名稱，不列原始輸入。格式錯誤為 ContractError。

此 checker 取得 private M 供本機研究用，**不是 witness-free VerifyIssue**；不驗 sid/rid 的
來源、quota/replay、I2 的 circuit、I3/I4/I5、freshness 或票證簽章。甚至一個被改壞 c3 的 C
仍可通過 key/pp identity 檢查，測試明確示範它同時被 TB2 I5 拒絕。接合端不得省略其餘 verifier。

## 3. GFR-01 與覆蓋案例

測試使用兩把正確 reference KeyGen 的公鑰，固定 ctx/sn/h/rid 並指定 u=0：raw C 相同，
I5 在 key B 成立，sk B 也解得同一 plaintext；傳入 key A 的 pp／bundle 配 key B record 時，
本 checker 以 `tpk_record_sha256` mismatch 拒絕。

同時更換 key 與 binding 自報 digest 仍會觸發完整 pp pin 或 bundle key mismatch。
若為研究測試把整份 bundle／pp／pin 都換成另一組一致輸入，結果仍僅 identity-only，
`purpose="production"` 仍拒絕；此結果不被稱為 configuration authentication。
兩組不同 pp 的 M header／d_M 不同，但本輪沒有簽章 verifier，不能宣稱實測了舊簽章拒絕。

| 驗收項目 | 本輪狀態 |
| --- | --- |
| A01–A04 strict packets、raw slots、nested metadata | Runtime Implemented／Tested；所有截斷位置、trailing bytes 與 header/digest mutations |
| A05–A08 key/pp/config identity、GFR-01 | Research equality checks Implemented／Tested；trusted configuration boundary 仍 OPEN |
| A09 authentication、A10 certificate、A12 B qualification | 未實作；只驗 exact opaque input identities，不接受為 production |
| A11 完整 pp、A13–A15 M/header/statement binding | Host research checks／digest tests 通過；簽章與 native constraints 未接合 |
| A16 完整 I1–I5 join | 未實作；沿用既有 TB2 I5，沒有用 host equality 代替 constraints |
| A17 rho／r／beta codecs | Pinned legacy18 canonical encoding 通過；CAP computation／I3 proof 未因此封閉 |
| A18 public/private partition | New statement dataclass 與 spec 對照；真正 B VerifyIssue 未改動 |
| A19–A22 opening／d_M authorization／durability | 未實作；沒有碰 opening／M6 store |
| A23 reuse／A24 production | 合法 u 值保留；common registry 未變，production/default 拒絕 paths 已測 |

## 4. 驗證與 evidence

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates/gf/research_abi_v0_1 -t tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/abi_v0_1/check_spec_v0_1.py
git diff --check
```

| Test run | Passed | Failed/errors | Skipped | Elapsed |
| --- | --- | --- | --- | --- |
| 新 research codec/binding tests | 30 | 0 | 0 | 1.494 s |
| Threshold targeted（含上述 30） | 90 | 0 | 0 | 12.839 s |
| Full regression | 766 | 0 | 12 | 759.285 s |

Full regression 共 778 項，12 項略過皆因對應 optional external artifacts 未安裝。
沒有為消除 skips 下載資料。完整測試啟動後，7 份新 source/test 的 bytes／SHA-256 均未變。
Source identity、文件連結、artifact scope 與 `git diff --check` 於提交前通過；raw logs 留在
repository 外，精確 log bytes／digest 與個別 skip reasons 列在本輪驗證摘要。

凍結 document checker 的 5 positive／40 negative report 與前一輪一致，沒有改寫既有 vectors。
完整來源 revisions／bytes／SHA-256 見 [source_index_v0_1.json](source_index_v0_1.json)；
本輪 code/test identities、命令、log identities 與受限 claims 見
[validation_summary_v0_1.json](validation_summary_v0_1.json)。Raw logs、keys、witnesses、PDF、
cache、assignments 與證書／attestation 均未加入 Git。

## 5. 狀態與後續

這是 bounded research implementation 與 regression evidence；沒有 external independent review、
native constraints、Evidence-sealed、Proof-closed 或 Production-closed 宣稱。
Root methodology／experiments／RESEARCH_STATUS 由 integration owner 更新；本文件提供理由、
命令結果與 current boundary，未覆寫 root canonical 或其他工作線 files。

下一關是針對此 exact implementation 做技術複核，再由 common/B/system owners 定義並接納
trusted authentication／key-origin 及完整 relation adapters。OA DKG、robust shares、多輪
transcript 與 TB3 threshold cryptography 尚未開始。
