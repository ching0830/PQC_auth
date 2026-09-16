# `R_access` holder-signature候選安全責任：D3 v0.1

日期：2026-09-16

狀態：research security-game checkpoint；非canonical protocol、非security proof closure

## 1. 安全結論

把舊access NIZK換成經ticket認證的per-ticket holder signature，在目前論文目標下是
**可論證的候選**，原因是現有core theorem不需要從access抽取原`k_hold`。但可替換的是
`G-ACCESS-AUTH`中的holder authorization責任，不是issuance SE-AoK，也不是舊exact
`R_access`本身。

新組合必須證明：

```text
certified ticket containing holder descriptor
+ collision-resistant descriptor binding
+ holder-signature unforgeability on exact HolderAuthCore
+ authenticated PQ AKE and bilateral key confirmation
+ linearizable one-time consumption
=> partnered, context-bound, at-most-once access acceptance
```

每個加號都是獨立責任。一般signature通過單元測試不能推出SE-NIZK、session-key
indistinguishability、one-use或end-to-end theorem。

## 2. 必須保留與可替換的extractor

| 邊界 | 是否保留extractor | 理由 |
| --- | --- | --- |
| `Pi_issue`對`R_issue,new` | 是，仍需PQ SE-AoK或最終精確定義要求的extractability | 認證hidden ticket、RID、trace ciphertext、blind request及`R_key`為同一witness |
| Blind-UOV CAP／well-built request | 是 | one-more／request binding reduction需要`r,rho`等witness |
| Access holder authentication | 可改成UF game，不必抽取`k_hold` | 目標是防止非holder授權新的request core |
| Trace opening | 不從access抽取 | opening依ticket中已認證的ciphertext及threshold gate |

如果論文未來要求「從每個accepting access transcript恢復一個特定秘密」、向adversary提供
simulated holder authentications後仍抽取、或需要zero-knowledge deniability，signature UF
不夠，必須另設proof-of-knowledge／simulation-extractable路線。

## 3. 新安全遊戲

### 3.1 `G-HOLDER-AUTH-UF`

Challenger建立誠實per-ticket holder key pair，經`R_issue,new`發行包含descriptor `D_H`的
ticket。Adversary控制network、relay及其他holders，可取得其他tickets，並依明定policy
查詢challenge holder對選定`HolderAuthCore`的合法簽章。

Adversary勝利，若honest FGS對challenge ticket接受一個`HolderAuthCore*`，且：

1. `VerifyTicketNew`及descriptor binding通過；
2. `HolderSig.Verify(pk_H,Core*,sigma*)=1`；
3. `Core*`未曾由challenge holder授權；
4. 沒有holder-key reveal，或reveal時點仍符合freshness predicate。

Reduction目標為holder signature的PQ EUF-CMA。若protocol把不同signature bytes視為不同
attempt，即使message相同，也需要SUF-CMA／non-malleability；較好的設計是把logical attempt
identity固定為signed core digest，讓同message的不同合法signature落在同一attempt。

### 3.2 `G-ACCESS-AUTH-new`

FGS在`ACTIVE`接受時，必須存在唯一partnered UE，雙方同意：

```text
ticket canonical digest
holder descriptor and pk_H
protocol/access/holder/AKE suite identities
system configuration and epoch
FGS identity and FGS authentication key identity
serving and authorization context
channel binding mode/digest
UE ephemeral KEM public key and FGS KEM ciphertext
request/response/session identities
server and client Finished transcript
```

歸約至少分解成：

- ticket不是合法issuance來源：PQ-RBBC certified-language／one-more term；
- `pk_H`不對應ticket descriptor：`H_bind` collision／second-preimage term；
- 新holder-authorized core：holder signature UF term；
- 偽造FGS或unknown-key-share：FGS authentication／AKE term；
- key mismatch仍通過：KDF／Finished PRF-MAC term；
- 同票建立兩個session：one-time store／state-machine lemma；
- context／suite替換：canonical encoding或上述authentication term。

`FGS_AUTHORIZED_PENDING`、`UE_ACCEPTED`與`FGS_ACTIVE`仍是不同事件。M2前永久消耗是
latency-first availability選擇，不應被holder signature美化成client已在線確認。

### 3.3 `G-ISSUE-ACCESS-PRIV-new`

至少分開三個observer：

- HNCC在issuance看見authenticated RID與blind transcript；
- network／relay看見access packet length、timing及routing；
- FGS看見ticket、per-ticket `pk_H`、holder signature及serving context。

為避免直接issuer-to-access link，`pk_H`、`q`及SN須在issuance proof中保持hidden，且每票
獨立產生。這只能防止直接identifier比對；timing、unique policy、packet shape、location及
HNCC–FGS collusion仍需獨立leakage model。公開signature也形成可轉交的event evidence，
不具deniability。

## 4. 攻擊／mutation責任表

| 攻擊 | 必須由何者拒絕 | 仍有的限制 |
| --- | --- | --- |
| 換ticket但保留`pk_H,sigma_H` | signed exact ticket bytes／digest | digest collision另計 |
| 換`pk_H` | ticket中的`q=H_bind(...)` | `H_bind` collision bound |
| 換holder suite／parameter revision | descriptor與signed core | downgrade policy必須由authenticated config提供 |
| 換FGS／FGS key ID | holder signature及M2 FGS auth | compromised FGS另由freshness定義 |
| 換UE KEM epk | holder signature | KEM validation及key erasure另證 |
| 換serving／authorization context | holder signature、FGS auth、KDF | hidden attribute policy不在此自動成立 |
| 完整重播M1 | same-attempt durable recovery | early burn／jamming DoS仍存在 |
| 同票不同attempt race | global CAS／linearizable store | signature本身不提供one-use |
| 同SN不同ticket race | `(ctx,sn)`與ticket digest uniqueness policy | 跨domain replication仍是system assumption |
| 同core重簽／變形signature | stable core-based attempt identity，或SUF | 現行v2 attempt ID含完整request，必須改版 |
| FGS自行捏造UE request | holder signature UF | FGS可重播holder已簽M1，但取不到UE KEM secret |
| 惡意HNCC替受害RID另發ticket | 本候選無法阻止 | 需要malicious-issuer non-frameability機制 |
| holder主動分享private key | 本候選無法阻止 | 軟體credential不具不可轉讓性 |

## 5. `R_key`的proof責任

### 5.1 ML-DSA-65

若`R_key`證明exact `KeyGen_internal(xi)`，需要：

- exact FIPS 204 revision及parameter digest；
- seed expansion、sampling、counter與rejection upper bound；
- canonical public／private key encoding；
- bounded trace超限時fail closed；
- 說明ZK只證明演算法一致性，不證明RBG uniformity；
- issuance proof成本與side-channel boundary。

若只做algebraic key consistency，security statement須限制為「知道一份與`pk_H`一致的
signing state」，不能宣稱public key來自FIPS KeyGen distribution。對honest challenge key
的UF reduction可由challenger依FIPS KeyGen產生；惡意holder key的validation則是不同責任。

### 5.2 FAEST-192s v3

必須精確約束：

- `k`為192 bits，`x`為128 bits；
- `not(k[0] and k[1])` key-domain rule；
- `x xor LE128(1)`的bit order；
- 兩次AES-192 evaluation及`pk=x||y`的48-byte canonical encoding；
- exact v3 parameter digest與signature parser；
- key／message被FAEST原生hash綁定的規格路徑。

FAEST signature源自argument of knowledge並不表示它是本專案所需的通用SE-NIZK；本候選
只使用完整FAEST signature的EUF-CMA contract。

## 6. Trace與core theorem的重證清單

新relation需逐項更新：

1. `TicketShape`接受新version、descriptor與固定長度；
2. `H_ticket,new` domain及payload vector；
3. I3對新digest的fork-specific request binding；
4. I4由SHAKE preimage改成suite-specific `R_key`；
5. I5的KDF、mask、KMAC及associated data改綁`D_H`；
6. certified-language theorem抽取`omega_H`而非`k_hold`；
7. issuer unlinkability hybrid隱藏`pk_H,q`；
8. trace soundness／GCCA使用新I5；
9. ticket one-more proof使用新canonical digest；
10. opening只依新ticket/ciphertext，不將holder signature當opening authorization。

`tau`-GCCA Game 1目前列出的`k_hold`可改為`omega_H`，但真正用來回答opening query的仍是
extracted trace plaintext／randomness。這是proof文字修訂，不是已完成的formal proof。

## 7. D3 attack cases與tests要求

下一個prototype至少必須有：

- wrong ticket、wrong `pk_H`、wrong `q`、wrong holder suite／pp digest；
- cross-version、cross-FGS、cross-role、cross-context、downgrade；
- mutated UE KEM epk、FGS KEM ciphertext、server／client Finished；
- malformed／alternate／trailing signature和public key encoding；
- bitwise-identical M1 retry、same-core re-sign、different-attempt race；
- same ticket及same SN並發；
- crash at reserve／commit／M2 publication／activation boundaries；
- issuer transcript不得直接包含稍後公開的`pk_H`或`q`；
- FGS無holder key時不能為新core製造valid auth；
- exact total bytes及每個field的ledger assertion。

Mutation tests只能證明implementation wiring，不等於UF／AKE／privacy theorem。

## 8. 尺寸與安全決策

`ML-DSA-65`應作第一個D4 implementation baseline：它已標準化，holder bytes較小，容易
建立兩套implementation interop。`FAEST-192s v3`應並行作對照，因其`R_key`與AES OWF
較適合issuance proof，但標準成熟度較低且線上多4,197 bytes。

目前不得選定production winner。只有在下列證據到齊後才可進入shared integration：

- 新完整ticket實際bytes；
- 兩候選真實keygen/sign/verify與wire bytes；
- `R_key` circuit成本；
- 完整M1/M2/M3或first-record bytes < 50,000；
- mutation／replay／concurrency evidence；
- access composition reduction獨立review；
- exact suite／provider／parameter identities與fail-closed parser。

## 9. 下一個checkpoint：D4 isolated handshake prototype

D4不得修改shared v0.2 parser或production registry。建議另建task-specific worktree與
experimental namespace，依序：

1. 凍結`HolderAuthCoreV3`及candidate ticket fixture的canonical bytes；
2. 先接兩個獨立ML-DSA-65 provider跑KAT／interop；
3. 產生per-ticket key、真實holder signature並驗證mutation；
4. 以現行ML-KEM／FGS auth候選序列化M1、M2、M3及first protected record；
5. 報告每個物件bytes、UE sign、FGS verify、peak memory及host identity；
6. 若沒有production PQ-RBBC ticket，只能同時報fixture實測與`T`參數化總量；
7. 再接FAEST-192s v3，以相同core、message flow與benchmark method比較；
8. D4通過後，另開D5研究`R_key` issuance circuit，不能由短signature反推發行成本。

## 10. Claim boundary

本文件完成D3的game／reduction責任與attack checklist；沒有完成新proof。狀態：

```text
relation_defined_for_research = true
holder_signature_substitution_proved = false
access_composition_proof_closed = false
production_ticket_measured = false
complete_handshake_measured = false
safe_to_modify_shared_protocol = false
Production-closed = false
```
