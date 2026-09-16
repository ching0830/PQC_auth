# GF key／profile／pp 接合驗收提案

本文件是 GFR-01 的具體 integration request，尚未成為已實作 ABI 或 production 接受流程。
來源與 pinned revisions 見 [技術複核](REVIEW_zh-TW.md)；所有現有 common／B／opening source
及 schema 保持原樣。不得只新增 `verified=True` 或把本文件存在視為已通過驗收。

## 必須分開檢查的三件事

1. **Byte identity**：profile descriptor、公鑰 canonical record、pp 的精確 digest／編碼。
2. **Trusted identity**：這些 bytes 是否是經驗證設定在該 epoch、用途、OA key ID 下授權的資料；key certification 亦須驗證其來源與適用範圍。
3. **Relation validity**：在已選定且驗證的 tpk 下，這個 C／AD／plaintext／u 是否滿足 I5。

GFR-01 顯示第 3 項不能代替前兩項。`u=0` 時，跨 key 的兩個 relation 都可能合法成立。
只有 profile ID 或一個自報 digest 也不提供 trusted identity。

## Candidate→common→B／opening 的資料流

| 階段 | 必須從可信來源取得／比較 | GF 尚待交付 |
| --- | --- | --- |
| 設定與 pp 解析 | 已驗證的 federation configuration、ci/ctx、epoch、OA key ID／role、issuer key；pp identity | 新 profile 的完整 trusted metadata mapping 與驗證邊界 |
| 公鑰選取 | OA key ID 對應的 canonical tpk record、profile digest、key certification；與 pp 中的 tpk digest 一致 | GF certificate／key origin 模型與 codec；目前只有 full-key reference |
| Statement 接合 | B statement 的 pp digest 指向上述同一份 pp；ctx 符合同一份 authenticated ci | 版本化 GF pp/relation/statement mapping，不擴大 public witness partition |
| I5 | 相同 tpk、profile、M.C、ctx、M.sn、M.h、rid 及 u；u 128 bytes | 新 witness descriptor、M encoding 與完整 constraints；不能沿用 368-byte NIED M |
| Opening | 驗證票證取得的 M／AD、authorization、canonical d_M、OA epoch/key/profile 與每個 participant 的 key identity 一致 | trusted TicketView/context、multi-round transcript、share correctness 與 durable replay |

Canonical core 的 ctx 是 `SHAKE256("PQ-RBBC/CTX"||Encode(ci),32)`；ci 包含 OA key ID
與 epoch，federation signature 驗證 `(ci,ctx)`。GF reference 的 `TraceInputs` 沒有這個
驗證器；本輪反例故意保留同一 ctx 但替換 pk，因此它不是已驗證 canonical 系統遭突破的證據。

B 的 production-inputs v1 已提供 `trace_public_key_sha256`、`trace_certification_sha256`、
issuer key digest 與固定 profile/relation 欄位，方向可供新 GF mapping 參考。
其現有 `TracePublicKeyV1` grammar 明確固定為 systematic Niederreiter matrix；不能把
GF public-key record 填入該欄或只替換 scheme 名稱便宣稱相容。

## 接合版本應具備的驗收案例

| 案例 | 需要的結果 |
| --- | --- |
| 合法 GF reference C＋合法綁定的 pp/ctx/profile/key/certification | 僅在對應研究整合 profile 中進入 I5；production 仍受獨立 qualification gate 控制 |
| u=0，I5 在 key A/B 都成立，但 trusted expected key=A、實際 supplied key=B | 在 identity／parameter checks 拒絕，即使 relation／decryption 成功 |
| tpk record 不同，但 caller 把自報 digest 一起換掉 | 與受驗證 pp／設定不一致，拒絕 |
| key ID 正確但 epoch、purpose／role、profile、key certification 不符 | 拒絕；不呼叫門檻 backend |
| 只改 statement 的 pp digest、保留舊 proof／witness | 參數／proof binding 拒絕；完整 constraints 與 proof 測試另由 B 提供 |
| 非 canonical key/profile encoding、trailing bytes、unknown version | 解析即拒絕，不容許等價 alternate bytes |
| 偽造 ctx，或 ctx 的已驗證 OA key ID 與 supplied tpk 不一致 | 設定綁定拒絕，不能只驗 32-byte 長度 |
| 重用 u 加密兩個 plaintext | Reference 關係可都成立；不得把 I5 當成 witness freshness 證明。誠實加密抽樣與惡意 witness 的遊戲量詞須另述 |

此表不是測試已完成的宣告。本輪已執行跨 key／witness reuse 的候選層反例，
common/B/opening 端到端 rejection tests 仍待 owner 在版本化接合實作後提供。

## 本輪處置

將 CR-GF-01/02/03 保留 OPEN，先完成 GF key/profile/pp 綁定與 witness/M ABI 的接合規格。
TB3 多輪實作未啟動；尚需 participant／corruption／setup／DKG、transcript、authorization、
share validity、replay／crash recovery 與具體 cryptographic assumptions 的設計審查。
此提案不要求把 tpk 偷加進 frozen v1 hash domain，也不刪除零 witness；任何演算法變體都必須
另立 profile、重新產生 vectors 並核對 proof hypotheses。
