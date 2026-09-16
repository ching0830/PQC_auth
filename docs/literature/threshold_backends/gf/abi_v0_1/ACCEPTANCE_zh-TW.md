# GF ABI v0.1 接合驗收矩陣

本表是 [規格](SPEC_zh-TW.md) 的驗收義務，**不是全部已測試**的聲明。
本輪 checker 只檢查文件的 offsets、framing、synthetic byte/digest consistency；
沒有 authentication、完整 cryptographic relation、B proof 或 opening 成功路徑。
原始 GF 加密／跨 key／reuse tests 的執行結果另外列在 [交付紀錄](DELIVERY_zh-TW.md)。

| ID | 觸發案例 | 必要結果與最早拒絕邊界 | 實作 owner／狀態 |
| --- | --- | --- | --- |
| A01 | frozen ABI 的 5 種 packet，fixed fields／nested shapes 正確 | document checker 可 structural round-trip；不得報 trusted accept | T：本輪文件 conformance |
| A02 | wrong magic/version/ABI/profile；長度短一、長一；固定 digest 為零 | strict codec 拒絕；runtime 與 document checker 必須分別測試 | T：document conformance；runtime OPEN |
| A03 | 把 2910-byte C record 或 TB1 envelope 填入 M raw-C slot | 拒絕，不剝除 header 後寬鬆接受 | T：runtime OPEN |
| A04 | 把 190-byte u record 或 836-byte error vector 填入 128-byte u slot | 拒絕；不得 truncate、pad 或套用 Hamming-weight constraint | T：runtime OPEN |
| A05 | u=0、key A/B 的 I5 都成立，trusted expected key=A 而 supplied key=B | identity check 拒絕，I5 或解密成立不能覆蓋它 | Common/system：OPEN；TB2 層跨 key 反例已測 |
| A06 | 同時替換 supplied key 和自報 key digest | 仍與 authenticated bundle／pp 不符，拒絕 | Common/system：OPEN |
| A07 | 以漂亮排版 descriptor 檔案 SHA-256 代替 crypto fingerprint；或只 hash key body/seed | 拒絕錯誤 identity domain | T/common：OPEN；本輪檢查兩種 descriptor identities 有別 |
| A08 | 改 key ID、epoch、role、purpose、issuer key 或 configuration digest；只驗 ctx 長度 | 設定／identity checks 拒絕；role/purpose 常數亦受 codec 限制 | Common/system：OPEN |
| A09 | configuration shape 合法但簽章不合法；或帶外 trust anchor 被 caller 替換 | trust verification 拒絕，不能只 `.validate()` 或返回 `verified=True` | System：OPEN |
| A10 | OA record byte identity 正確但 key-origin evidence 缺少、偽造、wrong model／epoch | evidence verifier 拒絕；不能將 parser 當 KeyGen／DKG certification | T/system：OPEN |
| A11 | bundle.common_parameters_digest 綁 capsule digest，而非完整 pp；pp 換掉 backend／relation | 精確完整 pp 及下游 identity 檢查拒絕 | B/system：OPEN |
| A12 | 舊 NIED full-relation manifest／ABI、fixture digest 或空 backend PP | B qualification gate 拒絕，無 Prove/Verify 成功路徑 | B：OPEN |
| A13 | 同一 C/ctx/sn/h，但改 M header.pp digest | Encode(M)、d_M 隨之變；舊簽章應拒絕；M/header/statement 同值約束不得省略 | T：本輪只驗 bytes/digest；B/ticket 簽章與 constraints OPEN |
| A14 | statement 綁 pp A，而 M header 綁 pp B | P0/I1 拒絕，不能只檢查 C 是否解得出 | B：OPEN |
| A15 | 只 hash M 尾端欄位，漏 ABI／pp header | I2 不成立；完整 relation mutation test 必須捕捉 | B：OPEN；本輪只驗 digest preimage 有別 |
| A16 | duplicated ctx/sn/h/rid/u wires 只在一份更動；c1 合法但 c2/c3/c4 被改 | 同一組 I1–I5 wires 拒絕，不能用 host assertion 代替 constraints | B：OPEN；TB2 component mutations 另有 tests |
| A17 | rho 長度正確但 CAP fingerprint/field encoding/root count 不正確；beta/r 不 canonical | pinned B codecs 拒絕；unified-tree 不可重標為 legacy18 | B：OPEN；本輪不驗 opaque rho/beta/r 的數學結構 |
| A18 | VerifyIssue 接口收到／要求私密 M/sn/h/C/d_M/u/k_hold | API／proof boundary 拒絕，不新增 public commitment 或 per-ticket PP | B：OPEN |
| A19 | opening request 自帶 h／AD／tpk 覆蓋已驗證 M；或只提供任意 ciphertext | gate 拒絕；backend touch count 必須為 0 | Opening：OPEN |
| A20 | 混淆 SHA256(T) 與 d_M；同一 M 配不同 transport/signature bytes | d_M 只綁 M；新 case authorization 必須綁正確 digest；舊 request 不隱式遷移 | Ticket/opening：OPEN |
| A21 | invalid ticket/case/purpose/expiry；無效 share 或數學不正確但簽章合法的 share | 驗證前不產生份額；combiner 不接受錯誤份額或內外 sn 不符 | Opening/TB3：OPEN |
| A22 | 多輪已送訊息後 crash/retry、participant／key／epoch 替換 | 必須定義並驗證 durable transcript/replay 規則；不能重用單次 abort 假設 | Opening/TB3：OPEN |
| A23 | 重用 u 加密不同 ad/plaintext | relation 可能都成立；honest sampler／security game 必須另述 freshness 與隱私限制 | T：已有 TB2 regression；不是 I5 拒絕義務 |
| A24 | 未完整接合時啟用 production 或把 full-key decrypt 包成 threshold API | 一律 unavailable；不能憑文件 conformance 或 test trust model 提升 claims | 全體：保持拒絕邊界 |

## 跨 owner 的具體交付項

- **T/common**：新 namespace 的 strict research codecs、record adapters、expected-profile/key/pp
  equality checks、mutation tests；不能取代帶外信任驗證器。
- **B**：接納或提出明確版本修正；以 GF manifest／backend PP 接上本版或另版完整 constraints、
  same-wire joins、proof statement，分開交付 witness evaluator 和 witness-free VerifyIssue。
- **System/ticket/opening**：受驗證設定來源、key-origin verifier、歷史 pp/key resolution、3005-byte M
  dispatch、d_M-bound signatures／case authorization、trusted h/AD view，以及多輪 gate。
- **Integration**：將本次選擇理由、驗證命令／結果、Defined-only claim 分別登錄 methodology、
  experiments、RESEARCH_STATUS；本分支只提供可審查輸入，不覆寫共用文件。

本次沒有代替其他 owner 填寫 acceptance、簽署 approval 或改動其 worktree。
