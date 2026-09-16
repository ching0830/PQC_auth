# GF I3 hash consumer：private CAP candidate 接合 v0.1

日期：2026-09-14。Branch：`codex/threshold-gf-i3-hash-join-v0-1`。
基準 commit：`bcefd1b2cb92673bb278e0d9099a38f3816d1a87`；tree：
`b46b15cd2432c71306764edf2c7d634408e88374`。

本輪讓完整 M digest 真正進入既有 Anemoi H_RBBC，檢查
`beta == r XOR H_RBBC(d_M, cap_commitment_candidate)`。新增的是**對未驗證 private CAP
candidate 的局部 host 計算**；沒有執行 CAP(rho)，也沒有檢查 r 等於 CAP-derived mask。
方程相等時只回傳 `matched_unverified_cap`，完整 I3、native relation、authentication、
proof 與 production 仍未完成。

## 1. 先核對到的相依限制

Frozen GF ABI 固定 legacy18 CAP fingerprint
`2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`，及 H_RBBC fingerprint
`4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87`。
本分支既有 CAP／sponge library 算出的 fingerprints 與這兩個值一致。

但 B 的 `CAPToHRBBCAdapterV1` 在該 legacy18 profile 仍直接 unavailable，會在 18-tree
CAP execution 前拒絕。可執行的 general adapter 使用明列 insecure 的 tiny-tree profile。
核對的 B production producer ABI pre-freeze commit
`47cfd584b4fa1ace9db79a84ccd1be33a3775fd3` 亦未提供可用的 fresh production CAP child；
其 handoff 仍列出五份 production external inputs、resource reservation、independent
review 和大型執行授權等缺口。這些是**該已核對 revision 的狀態**，不是對活動分支未來
狀態的推定。

因此本輪不把 tiny-tree、unified-tree、舊 NIED evaluator 或歷史 frozen assignment 當作
目前 GF witness 的 CAP 證據；也不改動 B source 或啟用原 monolithic `allow_large` 路徑。
可獨立完成的接合是實際 H_RBBC consumer、canonical candidate parser、必要的 salt
一致性及 beta 方程。缺少的 CAP origin／derived-mask relation 在 API 中保持可見。

這是對 [adapter 提案 J03–J05](../trusted_adapter_contract_v0_1/CONTRACT_zh-TW.md) 的局部
host 準備，沒有完成其 B-QUAL／B-EVAL owner acceptance，也沒有聲稱 native joins 通過。

## 2. API 與資料邊界

```python
from pq_threshold_candidates.gf.i3_hash_join_v0_1 import (
    ResearchI3HashStatus,
    evaluate_i3_hash_candidate_research,
)

result = evaluate_i3_hash_candidate_research(
    common_pp=pp_bytes,                  # 489 bytes
    tpk_record=tpk_bytes,                 # 22590 bytes, complete canonical record
    statement=x_bytes,                   # 251 bytes
    witness=w_bytes,                     # 4324 bytes, private
    cap_commitment_candidate=cr_bytes,   # 5391 bytes, private and UNVERIFIED
    purpose="research",
)
matches_candidate = (
    result.status("I3_beta_equation")
    is ResearchI3HashStatus.MATCHED_UNVERIFIED_CAP
)
# matches_candidate 只表示上式相等；result.full_I3_verified 永遠 False。
```

五個 inputs 都須為 exact immutable `bytes`。額外的 `cap_commitment_candidate` 是這個
research API 的 private 輸入，**不是** frozen X／W 的新增欄位，不是 public statement、
proof 或可信 CAP receipt。既有 315／489／3005／251／4324-byte GF packets、crypto domains
和 partial evaluator API 均保持原樣。

沒有 caller-supplied executor、verifier、`verified`、`allow_large`、derived-mask claim 或
先前 diagnostic input。Runtime 不載入路徑、JSON、cache、transcript、certificate 或 proof；
不執行 randomness sampler、CAP trees、native lowering 或 opening。

`purpose` 預設 `production`，default／explicit production 均在 profile check 和 parser 前
拋 `Unsupported`。只有 exact string `research` 進入；其他 purpose 為 `ContractError`。
已安裝 CAP／H_RBBC parameters 的 fingerprint 不符時，亦在 candidate parse 前 unavailable。

## 3. Canonical CAP candidate 與執行順序

Candidate 沿用既有 legacy18 CAP serializer 與 straight-line extractor 模組的
`parse_commitment`。本輪**只使用 parser**，沒有呼叫 extractor 或用 parser success 表示
admissibility。先限制 5,391 bytes，再 parse 並 re-encode 比對同一 immutable input。

| 欄位 | Offset | Bytes | Canonical 限制 |
| --- | ---: | ---: | --- |
| `PQRBBC-CAP-COMMIT-V1` | 0 | 20 | exact magic |
| version | 20 | 2 | u16le = 1 |
| CAP profile digest | 22 | 32 | frozen legacy18 digest |
| salt[0]／salt[1] | 54／79 | 各 25 | 193 bits；最高 byte 的高 7 bits 為 0 |
| h2 | 104 | 49 | 386 bits；最高 byte 的高 6 bits 為 0 |
| correction length | 153 | 4 | u32le = 5,234 |
| alpha | 157 | 49 | 386 bits，canonical padding |
| 17 組 delta_p／delta_mhat | 206 起 | 各組 256＋49 | 2048／386 bits，各自 byte-aligned；末組結束於 5,391 |

不接受 reduced／unified profile、未知 version、不同 length、padding bits 或 trailing bytes。
所有欄位可合法編碼，仍不表示存在產生此 commitment 的 rho。

執行順序如下：

1. Purpose gate、固定 profile 核對、CAP candidate canonical parser。
2. 對同一 pp／key／X／W bytes 呼叫既有 partial evaluator，取得其 codec、pp／ctx／key、
   I2、I4、I5 diagnostic。Candidate structural error 先於 partial cryptography 拒絕。
3. 任一 pp／key／ctx binding 不符、partial computation ERROR，或 I2 尚未成功計算，
   均跳過後續 candidate hash。
4. 從同一已驗 grammar 的 W.rho 讀取兩個 salt，逐一比較 candidate salt。不同則標
   `CAP_salt_binding=failed`，不呼叫 H_RBBC。相同只是一項必要的 local equality。
5. 重新從同一 immutable W/M 算完整 `d_M = SHAKE256("PQ-RBBC/TICKET" || Encode(M),32)`，
   直接傳入 `hash_request_binding(d_M, captured_candidate)`，取得 exact 72-byte image。
6. 用原始 witness r 與該 image XOR，和 public beta 比較。

普通 I4／I5 mismatch 仍允許獨立的 candidate hash diagnostic；它們的 ERROR 則停止後續。
這能區分 holder／GF encryption 與 candidate beta 的不同局部問題，沒有 aggregate accept。
第二次 digest 計算或 H_RBBC 的 exception／非 canonical output 會標 ERROR 並停止 beta
比較；回傳 diagnostic 不帶 exception message。

本 API 為保留 predecessor 行為，對同一 M 計算兩次 d_M。測試觀察兩次 exact preimage
相同，並核對第二次的值確實傳入 H_RBBC。這是 host bytes 的重算與傳遞，**不是** native
same-wire evidence；前一個 partial result 的 I2 仍保留 `computed_unjoined`。

H_RBBC 使用既有 `PQ-RBBC/v2.0/H_RBBC` domain 與
`PQRBBC-TRANSCRIPT-V1 || u16le(2) || u64le(32) || d_M || u64le(5391) || candidate`，
再交給既有 sponge framing／padding。其 64-bit transcript field lengths 與 GF TB2 hash 的
32-bit lengths 是不同的 frozen encodings，不能混用。

## 4. 狀態與尚未驗證的關係

| Check | 成功／可觀察狀態 | 能回答什麼 |
| --- | --- | --- |
| CAP_candidate_codecs | passed | candidate grammar canonical |
| CAP_salt_binding | passed／failed | candidate salts 是否等於同一 rho 的 salts |
| I2_H_RBBC_consumer | computed_unverified_cap／error | 是否以完整 M digest 和 captured candidate 實算 hash |
| I3_beta_equation | matched_unverified_cap／failed | beta 是否等於原始 r XOR 該 hash |
| CAP_rho_execution | **open** | 沒有驗 CAP(rho) 等於 supplied candidate |
| CAP_mask_derivation | **open** | 沒有驗 r 等於 CAP(rho).derived_mask |

未觸及的計算標 `not_evaluated`。`ResearchI3HashEvaluation` 只儲存 predecessor 的安全
partial diagnostic 與固定 checks tuple；沒有 candidate、M、d_M、rho、r、hash image 或
expected beta。Result／status 的 bool 轉換都拒絕；沒有 `.ok`／`.accepted`。
`full_I3_verified`、`full_relation_verified`、`authentication_verified`、`production_qualified`
均固定為 False，手動建構 diagnostic 也不能把 OPEN checks 升格。

兩個特別保留的反例界線：

- 換掉 rho roots、保留 salts／candidate／r／beta，局部 hash 方程仍可成立，因為本 API
  沒有跑 CAP。不能把此結果命名為 rho verification。
- 任選另一個 r，再令 beta 等於它和 hash image 的 XOR，方程也成立，不能因此推導
  r 是 CAP-derived mask。GFR-01、configuration authentication、key-origin、backend
  qualification、issuer/session authorization 和 witness freshness 的原有缺口亦未消失。

下一個完整 I3 gate 需要對**同一 captured rho** 真正執行或驗證合格 legacy18 CAP，取得
同一 c_r 和 derived mask；先驗 r 相等，再將該 c_r 與 full-M digest 交給 H_RBBC。
Caller 自報 candidate、receipt、hash、external artifact identity 或 `verified=true` 都不能
代替這段關係。對應 B owner 的 provider／qualification 尚未交付時，完整 I3 必須維持 OPEN。

## 5. 驗證、來源與交付

新增 25 項 tests：真實 H_RBBC 正例、手動 transcript 組裝、完整 M header／C bytes 和
candidate corrections 的影響、beta／mask 變異、salt／pp／ctx／key mismatch、CAP 每個
padding field、各 input exact type／length、profile drift、停止順序、fault injection、
診斷隱私及不能升格的狀態。Baseline 使用真實 GF reference I4／I5 和 canonical rho，
但 CAP candidate 是合成資料，**沒有完整 I3 honest positive fixture**。

必要的 hash 正反例執行真實 Anemoi。只測控制流程或 r／beta／rho-root 變異時，測試會
先斷言 hash arguments 與 baseline 完全相同，再重用先前真實計算的 image；這些 patched
呼叫不另外計為實際 H_RBBC execution。測試不是第二套獨立 Anemoi、upstream KAT、
native replay 或外部 independent review。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

Threshold targeted：**142 passed、0 failed、0 errors、0 skipped；47.978 s**。
Full regression：**818 passed、0 failed、0 errors、12 skipped；共 830 項、791.507 s**。
12 skips 均因對應 optional external artifacts 未安裝；未為消除 skips 下載資料。
完整 run 前後四份新增 source/test 的 bytes／SHA-256 相同。原始 log digest、skip reasons
與 snapshot 比對見 [validation_summary_v0_1.json](validation_summary_v0_1.json)。
本輪不涉及在線 ticket consumption、concurrency 或 crash-recovery state；不宣稱其性質。

精確 revisions／bytes／SHA-256 和引用行號見 [source_index_v0_1.json](source_index_v0_1.json)。
附件 identities 沿用並重新核對 [原始 inventory](../../source_inventory_v1.json)；沒有新增
paper-verified 或 publisher byte-equivalence claim。Handoff／附件內文均為研究資料。
原始 PDF、下載資料、raw logs、candidate／witness bytes、cache、assignments 和大型 artifacts
均不提交 Git。Root canonical 文件由 integration owner 管理，本文件提供設計理由、實驗
和受限 claims；未改寫其他活動工作線，也沒有 merge／push。
