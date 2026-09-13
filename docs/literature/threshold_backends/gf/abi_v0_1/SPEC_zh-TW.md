# GF key binding 與 issuance ABI 候選規格 v0.1

日期：2026-09-13。基於 `ddb1336ff5a32ca5b2d50bbe31f3d5d0c07a6b25` 的
[TB2 複核](../review/REVIEW_zh-TW.md)。本輪定稿的是 **T 工作線的候選規格**；
尚未改成 repository canonical contract，也未獲 common／B／opening owner 接納。
實際 wire grammar 在 [contract_v0_1.json](contract_v0_1.json)；來源 identities、
引用行號及驗證結果見 [交付紀錄](DELIVERY_zh-TW.md)。

## 1. 本輪決定與適用範圍

1. 加密 profile 保持 `gf-hybrid2-pompeii-d4-shake256-otp-ref-v1`。Pompeii、Hybrid2、
   hash inputs、record、合法 `u=0` 均沿用 TB2；新格式是系統接合設計，並非 paper 格式。
2. `M_GF` 直接內含 **2848-byte raw C**；I5 witness slot 使用 **128-byte raw u**。
   不巢狀放入 2910-byte ciphertext record、190-byte witness record 或 TB1 estimate envelope。
3. 新 M header 綁 ABI fingerprint **及完整 common pp digest**。此 32-byte pp 欄位也進入
   `d_M`，讓相同 raw C 在不同 pp 下的簽章訊息不同；這是新增的 encoding metadata，
   必須由 B／ticket owner 用新版本接合，不能假稱現有 368-byte M 已相容。
4. 公鑰 identity 是完整 **22590-byte canonical public-key record 的 SHA-256**，
   不 hash 22528-byte body、seed 或 key ID 作替代。Trusted identity 另由已驗證設定提供。
5. 本版 issuance bridge 明確對準 B 已有的 **legacy 18-tree CAP shape**：beta/r 72 bytes、
   rho 1036 bytes。這是有限的介面比較基準，沒有選定 production CAP；unified-tree 必須另版。
6. PP／statement／witness 規格均固定；完整 relation manifest、backend PP、可信 key-origin
   evidence 及 authentication adapter 尚缺，故沒有可接受的實際整合 PP 或 proof。

所有生產功能保持 unavailable。僅文件 conformance checker 有結構處理程式；它不提供
runtime codec、signature／certificate verifier、ProveIssue、VerifyIssue 或 opening API。

## 2. Identity 與精確編碼

所有固定大小欄位依 JSON 的 `offset` 順序串接。整數採 little-endian；magic 含一個末尾 NUL；
wire version 為 u16 `1`，是本候選 namespace 的第一版，不代表原系統 v1 接受此格式。
不接受未知／alternate version、profile、錯誤固定長度、truncation、trailing bytes、額外欄位。
非零 key IDs／digest 的要求依 JSON `nonzero`；sn/u 的全零值在此 codec 層不排除。

`abi_sha256 = SHA256(CanonicalJSON(contract_v0_1.json))`。CanonicalJSON 為 ASCII、
排序 keys、`,`／`:` 無空白、`ensure_ascii=true`、無末尾換行；拒絕 duplicate keys、NaN／Infinity。
文件沒有自含這個 digest，故無 self-hash cycle。其實際值記錄在 `validation_summary_v0_1.json`。
修改任一 normative contract 欄位會改變 ABI identity，不能沿用舊 vectors。

Crypto descriptor fingerprint 為
`3077ddb7e9f90c2a551c0fccff8719655b5e852394aa4e9326c9a7801225a9b7`，
依 TB2 `descriptor_sha256()` 的 compact JSON 規則；它**不同於** pretty JSON 檔案 digest
`999ff0f050044b022bf7ece99cb8b44d4d6e704295b79e7b92926737bfcfa1cc`。
來源檔案 SHA-256 與 protocol fingerprint 必須使用不同欄位名稱。

| 物件 | 精確 bytes | 內容與用途 |
| --- | ---: | --- |
| `trace_binding` | 315 | magic/version/ABI；crypto profile、configuration identity、ctx/epoch、OA role/purpose/key、issuer key、key-origin evidence |
| `common_pp` | 489 | magic/version/ABI；完整 binding、issue backend PP digest、GF full-relation manifest digest、CAP／H_RBBC fingerprints |
| `ticket_m` | 3005 | magic/version/ABI/pp digest，然後 ctx/sn/h/raw C |
| `issue_statement` | 251 | magic/version/ABI；pp digest/ctx/sid/rid/beta |
| `issue_witness` | 4324 | magic/version/ABI；完整 ticket_m、r、rho、k_hold、raw u |

### M 與 witness 的唯一 interpretation

```text
Encode_GF(M) = "PQ-TH-GF-M\0" || u16le(1) || abi_sha256[32]
            || common_pp_sha256[32] || ctx[32] || sn[16] || h[32] || C[2848]
C           = c1[2560] || c2[128] || c3[32] || c4[128]
d_M         = SHAKE256("PQ-RBBC/TICKET" || Encode_GF(M), 32)
ad          = ctx || sn || h                       # 80 bytes; no M header
plaintext   = rid || sn                            # 48 bytes
u           = 128 bytes, 4*256 coefficients, lsb0  # private; no DEM coins
```

M offsets：magic 0、version 11、ABI 13、pp digest 45、ctx 77、sn 109、h 125、C 157。
Witness offsets：magic 0、version 17、ABI 19、M 51、r 3056、rho 3128、k_hold 4164、u 4196。
所有 range 以 half-open `[offset, offset+bytes)` 解讀。JSON 為完整欄位表。

Full witness 的 rho 必須另外通過 pinned CAP decoder：1036-byte 長度本身不證明 field
elements、18 roots 或 profile 正確。r/beta 亦須通過 B 的 field codec；M/C 的形狀不證明 I5。
不得將 u 當成 Niederreiter error vector，亦不得套用 weight=128 約束。

## 3. 從可信設定到同一份 pp／key

Binding 的 `purpose=1` 固定表示 non-threshold research reference；`oa_role=5` 對應
`KeyRole.OPENING_ENCRYPTION`，只表達預定角色，沒有宣告此 full key 是 DKG output。

候選接受流程必須按以下順序，以同一份已 capture 的 bytes 做 digest、strict parse、
binding 和下游計算。不能驗完 pathname 後重新開檔取另一份 key／pp。

1. **信任起點**：從帶外設定取得 configuration verification key；驗證完整 authenticated
   initialization 的簽章和角色分離。來源的 `.validate()` 只做形狀檢查，不足以建立信任。
2. **完整 pp**：驗證 `SHA256(common_pp_bytes) == bundle.common_parameters_digest`。
   315-byte binding capsule 的 digest 不能代替完整 489-byte pp digest。
3. **設定一致**：binding.configuration_sha256 等於 `SHA256(configuration.encode())`；
   binding.ctx 等於 `SHAKE256("PQ-RBBC/CTX"||configuration.encode(),32)`；epoch、OA key ID、
   issuer key ID 對上同一 configuration 與 bundle。域／policy／expiry 延用該 configuration。
4. **公鑰與角色**：strict parse TB2 public-key record；其 SHA-256 同時等於 binding.tpk digest
   與 bundle 的 `OPENING_ENCRYPTION.public_key_digest`。Issuer digest 亦對上獨立角色。
   profile/ABI 須匹配固定 allowlist，不能信任 caller 把 key 與自報 digest 一起替換。
5. **key origin**：以 exact digest 取得外部 evidence，驗證其可信來源、profile、OA key ID、
   epoch、purpose、record identity 及所宣稱的 KeyGen 模型。Reference decoder 只驗矩陣形狀；
   不驗生成關係、T1 failure/bad-key 或 DKG。Certificate codec／verifier 未交付時停在 OPEN，
   不接受一份只有 `verified=true` 的 JSON。本輪不製作 certificate 或 reviewer attestation。
6. **B inputs**：backend PP 與 GF full-relation manifest 的 exact digests 必須匹配 pp，
   再驗它們的 namespace、statement/witness ABI、setup、proof/backend qualification 與同一
   CAP/H_RBBC profile。舊 NIED manifest、空值、fixture digest、檔案存在或 parser success 都不足。
7. **statement／M**：statement.pp digest、M header.pp digest 都等於步驟 2；M.ctx 等於
   statement.ctx 與步驟 3。I1–I5 在同一組 wires 上成立，才能交由 B 的 proof 接受流程。

上述驗證器缺少、例外或出現矛盾都應拒絕；其研究測試可使用明示 fixture trust model，
不可藉旗標穿越 production 邊界。PP/config/evidence 必須為該 anonymity set 的共同輸入，
不可納入 rid、sid、sn、h、C、u 或每張票的 d_M。

### 避免 identity cycle 與輪替歧義

依賴順序是：crypto/ABI profiles、keys、configuration → key-origin evidence → binding →
backend PP／GF relation manifest 與 common pp → authenticated initialization → statement/M。
Configuration 本身不含 bundle 或 pp digest；key-origin evidence 不可反向包含最終 common pp
或 authenticated initialization digest。Backend PP／GF relation manifest 亦不得反向 hash
這個 common pp；其可信驗證要求由 B 使用已選定 profile、keys 與 specification identities 表達。

新的 OA key／pp 需可區別的治理版本並保留舊票解析所需的歷史設定；拒絕同一可信 lookup key
映射到互相矛盾的 artifacts。M 的 pp digest 防止相同 C 因 pp 輪替而沿用原 d_M，並不代替
設定驗證或自動允許 revoked key。具體歷史 key resolution／revocation policy 由 system owner 定義。

## 4. I1–I5 與 public/private partition

語意 statement 維持 `x=(pp,ctx,sid,rid,beta)`；witness 為 `(M,r,rho,k_hold,u)`。
Issuer 接受 rid/sid 的真實驗證、quota/replay 仍是 B／system 義務。

| 約束 | 本候選必須綁定的內容 |
| --- | --- |
| P0/P1 | 可信完整 pp、已選定 relation／ABI／backend；statement 與 M header 的 pp/ABI equality |
| I1 | exact M grammar、fixed GF profile、同一 ctx/sn/h/C wires；M header 亦受約束 |
| I2 | 對完整 3005-byte M 計算 `H_ticket`；不可只 hash 尾端 2928-byte fields 或 2848-byte C |
| I3 | 同一 I2 輸出 m、同一 r/rho 與 public beta；pinned legacy CAP→H_RBBC full relation，不能採 test hash-shape adapter |
| I4 | M.h=`SHAKE256("PQ-RBBC/HOLD"||k_hold,32)`；同一 M.h 進 I5 AD |
| I5 | 固定 tpk；由同一 128-byte u 計算 Pompeii 和 H/H'/H''/G；ad=`ctx||M.sn||M.h`，plaintext=`rid||M.sn`；比較全部 c1–c4 |

不得用 Python boolean、precomputed C/digest 或未受約束的 duplicated wires 代替 constraints。
VerifyIssue 仍只接收 public parameters、statement、proof；不接收 M、sn、h、C、d_M、u 或
k_hold。新增 M header 的 pp digest 本來就是 public pp identity，不需另公開 M commitment。
這不改變 M 在完成 issuance 後隨 ticket 出示的角色。

## 5. GFR-01 的處置與 opening 接合

`u=0` 時兩把 key 的 raw C 可相同，此事仍由 TB2 regression 接受。新 proposal 有兩層義務：
外層 trusted key/pp checks 拒絕不符合 expected identity 的 key；若兩份不同 pp 各自合法，
M header 不同會使簽章輸入 bytes 不同（digest 相同須另涉及 hash collision）。
本輪 layout fixture 只核對這個 byte/digest 差異，沒有實作 trusted signature／key certification。

Opening owner 的新 trusted view 至少須從**同一次完整 VerifyTicket** 取得
`Encode_GF(M), d_M, common_pp_sha256, abi_sha256, ctx, sn, h, C` 及已解析的 OA/issuer binding。
AD 必須由這份 M 導出；request 不得額外提供可覆蓋的 h／AD／pk。
Case authorization 必須綁 `d_M`、case、evidence、purpose、expiry，然後才進入有 durable
replay 規則的多輪 backend。Participant key identity、share validity、transcript、crash recovery
仍是 TB3 的後續設計，沒有在此用 full-secret-key 解密替代。

唯讀 `ecab1d9` 的 ticket verifier 已分出 payload digest 與完整 transport digest，仍只支援
368-byte NIED M；其 TicketView/context 尚缺 h／AD，opening request 仍使用 SHA256(T)。
因此 IR-01/02/03/05 仍需新版本接合；不得直接把舊 `ticket_digest` 欄改成新 d_M。
若保留 transport identity，明確命名 `transport_ticket_sha256`，它不能取代 M6 的 d_M。
VerifyTicket 仍 stateless；不新增 one-use、AKE 或 access-state 宣稱。

## 6. 成本與 migration

M bytes = `80+2848+77 = 3005`；77 是 magic/version/ABI/pp header，不是實測 proof overhead。
與未 framed 的 GF fields 2928 bytes 相比增加 77；與 NIED M 368 相比增加 2637。
若僅代入 provisional sigma=11644，`M+sigma=14649`，**仍不含**未凍結的 ticket transport，
不是完整 ticket wire size。PP489、public key22590、witness4324 分別是 setup、setup、offline
issuance bytes；不能加進 satellite online ticket。Proof size／rounds／runtime／memory 未量測。

Common owner 需新增 reference-only registry identity；B owner 需新 PP／statement/witness/proof
namespace、M hashing、full constraints 與 join；ticket/opening owner 需新 M dispatch 和 trusted
view。所有舊 IDs、vectors、CAP evidence 與 NIED codecs 保持原語意，不自動升格或重標。
若改用 unified-tree、其他 DEM 或 transcript，另立 ABI/profile，重新作 vectors 和 proof 適用性審查。

## 7. 成熟度與下一關

候選 grammar／binding requirements：**Defined**。文件結構驗證：完成後見交付紀錄。
Runtime codec、trusted binding、完整 I1–I5／B／opening integration：**未實作**。
Evidence-sealed、Proof-closed、Production-closed：**false**。

下一個 bounded task 是在 T 自有 candidate namespace 實作此格式的 strict research codecs
與 key/pp mismatch tests，production 入口仍拒絕；跨 owner 的 adapter 需依
[驗收矩陣](ACCEPTANCE_zh-TW.md) 審查接納後實作。TB3 多輪 cryptography 尚未啟動。
