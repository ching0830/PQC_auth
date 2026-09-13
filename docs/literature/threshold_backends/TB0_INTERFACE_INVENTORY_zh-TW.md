# TB0：Threshold backend 介面盤點

盤點日期：2026-09-13。Canonical base 為 local `main`
`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`。本工作線基於來源稽核 commit
`853cf2f20f914704ed9b001d0be87d57f04e2e8a`，其相對 main 只新增四份來源文件。
主 checkout 的 thesis-learning 工作另有進度，未作為本次 base。

原論文的核對結果與十項 findings 見 [來源稽核](HANDOFF_VERIFICATION_zh-TW.md)。
既有十九份 canonical／reference 來源的 bytes、SHA-256 於本次 worktree 重核一致。
新增介面來源及未整合 B 分支的精確 revision、bytes、digest 見
[TB0 repository 索引](tb0_repository_sources_v1.json)。以下行號均指這些已釘選版本。

## 既有 opening 能力

| 位置 | 已有行為 | 缺口與 claim boundary |
| --- | --- | --- |
| `src/pq_rbbc/opening/interfaces.py:40` `TicketView` | `ticket_digest,ctx,visible_serial,trace_ciphertext,issuer_key_id` 及欄位形狀驗證 | 無 `h` 或 canonical AD；dataclass 本身不證明票證驗證成功 |
| 同檔 L60 `TicketVerifier` | `verify(ticket)->TicketView|None` Protocol | 注入邊界；main 此模組未提供完整 production VerifyTicket adapter |
| 同檔 L120 `ThresholdOpeningContext` | member、opening key、epoch、request/ticket digest、case、ciphertext | 未攜帶 `ctx,sn,h,ad`；不能由這些欄位重建同一張已驗證票證的 AD |
| 同檔 L169 `ThresholdShareBackend` | 單次 `create_share(context)` | Protocol 定義；GF／UT／NIED 的分散式計算尚無實作或多輪協定 adapter |
| 同檔 L177 `ShareVerifier` | 驗證 opening key、message、authentication | API 未另表達 mathematical share validity；驗證簽章不代表份額符合密碼學關係 |
| 同檔 L204 `ThresholdReconstructionBackend` | `reconstruct(ticket,shares)->DecodedTrace` | 抽象 reconstruction；docstring 限定 Niederreiter，未形成 candidate-neutral production ABI |
| `gate.py:34` `OpenShareService` | 嚴格 request codec、trusted bundle、ticket／ctx／epoch／key／expiry／authorization 檢查後，才 reserve replay 並呼叫 backend | 已實作 gated control flow，非真正門檻解密 |
| `gate.py:161–209` | reserve → context → create_share → encode → commit → return；backend error abort；commit error 不回傳 share、也不 abort | 單次本機呼叫的故障處置。多輪協定中「已送出部分訊息」後的 abort／retry 語意未定 |
| `combiner.py:26` `OpeningCombiner` | threshold 數量、member 去重、key／epoch／ticket／case／request 綁定、share authentication、reconstruction、trace authentication、serial 檢查 | 仰賴注入的 backend 與 verifiers；不證明錯誤份額可被數學辨識或 robustness |

`tests/system_modules/opening/_fixtures.py` 使用固定票證、hash/checksum share、固定解碼結果
及記憶體 replay store。29 項測試驗證上述 codec 與呼叫順序、拒絕及例外路徑。
`test_in_progress_parallel_reservation_is_treated_as_replay` 是既有 reservation 情境模擬，
沒有跨 process 的線性一致性或斷電恢復證據。

## 狀態分層

| 研究對象 | Defined | Instantiated | Implemented | Tested | Evidence-sealed | Proof-closed | Production-closed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Canonical T1–T4 與 I1–I5 要求 | 是 | 視候選而 OPEN | 不由定義推得 | 不由定義推得 | 本次無新 seal | 候選適用性 OPEN | 否 |
| Opening request/share codec 與 gate/combiner 控制流程 | 是 | 具體 byte grammar | 是 | 29 項 fixture regression | 既有 deterministic manifest/vector；未新增 seal | 不含 crypto closure | 否 |
| 真正 OA DKG／share correctness／distributed decoder | 抽象要求 | OPEN | 否 | 無本後端實測 | 否 | OPEN | 否 |
| TB1 research envelope／trace codec／accounting | 是 | 僅共同格式、條件式算術 | 是 | 新增 28 項 | 未作 portable seal | 不適用於 crypto 證明 | 否 |
| TH-GF／TH-UT／TH-NIED cryptography | 候選草案 | OPEN | 否 | 無 | 否 | OPEN | 否 |

## Integration requests

**IR-01：同一份已驗證票證的 AD。** Opening owner 應規劃新的版本化 TicketView/context：
從完整 VerifyTicket 的同一份 canonical `M=(ctx,sn,h,C)` 取得欄位；cross-check key/profile、
`ad=ctx||sn||h`、內外 serial。不能由 request 額外傳入未驗證的 `h`，也不能只增加一個
`verified=True` 旗標。新 TB1 `TraceInputs` 僅檢查形狀和 serial 一致，並非此 adapter。

**IR-02：多輪 session／replay。** 候選需提交 transcript、round、participant set、threshold、
epoch／key／candidate／profile／request／case／ciphertext／AD 的綁定及錯誤／中止規則。
Opening owner 再決定同步 encapsulation 或版本化 start/advance/finalize ABI；durable replay
reservation、訊息重送與 crash recovery 必須與已發出的訊息一致。不得把各 round 當成新授權，
也不得把 `create_share` 包一層 loop 就宣稱整合完成。TB1 方法全部拒絕，未凍結 transcript。

**IR-03：Authentication 與 mathematical validity。** 分別定義 share sender authentication、
well-formedness／correct computation 的判定與 evidence，交給 robust combiner 處置。
有效簽章的惡意份額仍需拒絕；T4 未由現有 `ShareVerifier` 的型別自動成立。

**IR-04：KDF metadata drift。** Core trace 式、reference、frozen vector／source-transition tests
均為 `Z[0:48]` pad、`Z[48:80]` MAC key。`gate.py:255` 及 conditional-opening manifest 仍有
`trace_kdf_80_byte_split_order_unresolved=true`。這是需由 owner 整體重驗後更新的 metadata
差異；本次不改 flag、source 或 sealed manifest。原始定位見來源稽核 F-08。

**IR-05：完整 ticket digest 與 canonical `d_M`。** 新增 finding：`request.py:93` 的
`canonical_ticket_digest(ticket)` 計算 `SHA256(完整 ticket bytes)`；gate 要求 TicketView
與它相同。Core L322–325、L521–525 及 one-time state spec L38–43 定義的則是
`d_M=SHAKE256("PQ-RBBC/TICKET"||Encode(M),32)`，不含 signature bytes。
兩者不能因同為 32 bytes 而互換或共用「canonical ticket digest」名稱。若完整 ticket digest
仍作 transport/request 綁定，需另命名，並明確把 authorization、share、opening 與 M6 state
的 canonical `d_M` 接合。此 finding 不單憑介面差異宣稱存在可利用攻擊；owner 必須選定
新版本編碼、migration 與 negative vectors，不能只改 hash function 而沿用舊 vectors。

**IR-06：B issuance ZK 的共同接點。** 唯讀觀察 branch
`codex/pq-rbbc-issuance-zk-backend-preflight`，tip
`fc59ff0c7a8fba8bc443c488e37f9a148f238753`；未 import、merge、執行或修改該工作線。
`src/pq_rbbc_issuance_zk_backend_preflight.py`：

- L247 `IssuePublicParametersV1` 綁定 backend/version/security profile、ABI digest、relation manifest、setup。
- L300 `IssueStatementV1` 為 ABI digest、PP digest、`ctx,sid,rid,beta`；沒有公開 M。
- L339 `IssueWitnessV1` 固定 ticket payload 368、blind mask 72、CAP randomness 1036、holder key 32、error vector 836 bytes。
- L452 `IssueZKBackend` 與 L507/529/563 wrappers：`Setup / ProveIssue / VerifyIssue`；Verify 不取得 witness；production allowlist 為空。
- 測試 backend 為明示不安全的 digest placeholder，不構成 I1–I5 relation proof。既有 v2.37 fixture 的 sid 來源及 complete relation join 亦未因此封閉。

候選與 B 唯一需要共享的是**同一個 I5 encryption relation 及其編碼／witness descriptor**，
而非分享 secret key 或改寫 B 的 proving 引擎。後續 change request 至少要有：

| 項目 | 需確認的綁定 |
| --- | --- |
| PP／statement identity | candidate、profile、tpk identity、版本、relation digest 進入 B 的 PP／relation namespace；public partition 仍為 canonical `pp,ctx,sid,rid,beta` |
| Witness descriptor | GF 的底層 message／randomness、UT 的 KEM／DEM coins、NIED 的 error vector；exact grammar、bounds、canonical encoding 均待候選確定 |
| I5 | `C=Enc(tpk, ad=ctx||sn||h, plaintext=rid||sn; witness)` 的實際 relation；與 I1–I4 的同一組 M、sn、h、rid wires 連接 |
| Variable ciphertext | 研究 envelope 並未加入 canonical M；若採用，payload／envelope bytes 計入 M 與 witness 新 ABI，不能塞入既有 368-byte 欄位或丟失 profile |
| Verification boundary | `VerifyIssue` 仍不接收 witness；禁止公開 M、host assertion 替代 constraint、或把 reference check 當 ZK proof |

**IR-07：Root canonical 更新權責。** 本工作線只提供候選文件及 checkpoint。整合 owner 後續
將設計理由登錄 methodology、命令／結果登錄 experiments、受限狀態登錄 RESEARCH_STATUS，
並依 roadmap 決定候選 reference 階段。這些共用文件沒有被此 literature/contract 工作線覆寫。
