# Satellite access v0.2 reconciliation execution-context checkpoint

日期：2026-09-16

狀態：Implemented／Tested（authenticated-executor／trusted-clock contract boundary）；
非concrete operator authentication、非trusted-clock instantiation、非Production-closed

基準parent：`95ed75d9676035c2f21c14ddcb50199c047bda21`

## 1. 對應的protocol／系統位置

這不是UE–FGS的M1／M2 satellite online path，也不修改`R_access`、ticket或AKE。它位於FGS
營運面的expired-reservation recovery：當worker在reserve後、grant commit前失敗，operator或
未來scheduler執行bounded reconciliation，將確定沒有成功publication的expired reservation以
generation fence安全移出active view。

前一checkpoint已用single-host lease限制同一invocation的active executor，卻仍直接接受caller
提供的`owner_id`及沒有identity的clock object。本checkpoint新增一個先於lease runner的
execution-context gate，回答「誰被允許執行」及「lease時間屬於哪個可信domain」的可執行介面。

## 2. Canonical execution scope

`ReconciliationExecutionScopeV2`固定：

```text
format
system_context_digest[32]
replay_store_id[32]
reconciliation_journal_id[32]
clock_id[32]
credential_verifier_id[32]
batch_limit / minimum_stale_seconds
lease_seconds
renewal_margin_seconds
```

所有identifiers必須非零、exact 32 bytes。Lease policy沿用1..86400秒與
`renewal_margin_seconds < lease_seconds`。Canonical ASCII JSON採sorted keys、無空白、lowercase
hex；unknown／missing fields、alternate spacing、uppercase hex及trailing bytes拒絕。Scope digest：

```text
SHAKE256(
  "PQ-SAT/FGS-RECONCILIATION-SCOPE-DIGEST/v0.2"
  || Encode(scope),
  256
)
```

Scope同時綁定coordinator的`batch_limit／minimum_stale_seconds`，避免持有credential的caller在
新invocation尚未建立intent前替換candidate上限或staleness policy。Store／journal IDs是
credential authority授權的configuration identities。目前reference沒有
authenticated system-configuration scope provider，也沒有production adapter可attest實際Python
object或database instance等於該identity，故不能把此綁定擴張成trust-root或host／database
attestation claim。

## 3. Executor authorization及credential

Canonical authorization包含：

```text
invocation_id[32]
execution_scope_digest[32]
operator_id[32]
executor_instance_id[32]
credential_id[32]
not_before
not_after
```

有效區間為`[not_before, not_after)`且不得為空。Credential envelope攜帶exact authorization bytes
及opaque authentication。Verifier輸入固定為：

```text
"PQ-SAT/FGS-RECONCILIATION-EXECUTOR-AUTH/v0.2"
|| Encode(authorization)
```

Authentication scheme及public-key trust anchor是external backend責任。本checkpoint只固定
bytes／protocol及fail-closed call boundary，不配置測試signature為正式operator credential。

Lease owner ID不再由credentialed runner的caller傳入，而是：

```text
SHAKE256(
  "PQ-SAT/FGS-RECONCILIATION-OWNER-ID/v0.2"
  || Encode(authorization),
  256
)
```

因此改動invocation、scope、operator、executor instance、credential或validity interval都產生
不同owner ID。相同credential被複製到兩個process仍會導出相同ID；unique credential issuance、
single-use presentation或process attestation尚未完成，machine claim維持false。

## 4. Fail-closed processing order

`CredentialedLeaseFencedResumableReconciliationRunnerV2`固定：

```text
pin clock_id and credential_verifier_id to execution scope
  -> require both backend production_ready flags
  -> strict decode credential
  -> require exact invocation_id, scope digest and coordinator policy
  -> sample clock once
  -> require not_before <= observed_at < not_after
  -> verify exact domain-separated authorization
  -> derive owner_id
  -> enter lease-fenced resumable runner
```

以上任一步失敗，都在建立intent／plan／lease及任何replay mutation前回傳`REJECTED`。Verifier只
接受literal `True`；整數1、false、exception、錯誤output或identity mismatch都不跨越gate。

初次authentication-time clock sample由lease acquisition重用，避免在credential check與lease
check之間無意多取樣。後續每次lease `assert／renew`及fenced progress／receipt前都再檢查：

- 同一runner內clock不可倒退；
- authorization仍位於半開有效期間；
- 原有current owner／generation／deadline lease條件仍成立。

若replay item已完成、下一次clock sample才發現credential expired或clock rollback，progress write
會fail closed並回傳`AUDIT_UNCERTAIN`；原exact plan、replay generation fence及後續takeover仍用
前一checkpoint的resume機制收斂。這不等於能撤回已經開始的replay call。

## 5. 測試與evidence

測試環境沒有external artifacts，使用明確的test doubles模擬structurally-ready clock及credential
verifier。它們只驗證composition，不是production backend qualification。

- execution-context focused：17 passed、0 skipped／failures／errors（0.449秒）；
- reconciliation adjacent：87 passed、0 skipped／failures／errors（3.232秒）；
- access system regression：366 passed、0 skipped／failures／errors（18.300秒）；
- repository-wide regression：1043 tests，其中1031 passed、12個既有optional skips、
  0 failures／errors（780.162秒）。

定向coverage包含三層canonical codecs、scope digest／owner derivation、unknown／trailing／uppercase
mutation、empty／zero／time bounds、exact authentication message、honest execution、authentication
mutation、false及nonboolean verifier result、backend exception、invocation／scope／clock／verifier ID
mismatch、unready backends、not-yet-valid／exact-expiry credential、mid-run expiry、clock rollback及
terminal retry重新authentication。

## 6. Claim boundary

可以宣稱：

- credentialed入口不接受caller覆寫raw owner ID；
- exact authenticated authorization綁定invocation、scope、operator、instance、credential及時效；
- coordinator的batch／minimum-stale policy必須等於credential scope；
- clock／verifier identities及readiness在任何execution mutation前檢查；
- 每次lease clock sample都檢查同一runner單調性及authorization validity；
- failure path保持reconciliation state不變，或在item已執行後依既有audit-uncertain／resume語意收斂。

不可宣稱：

- 已選定或實例化operator credential signature／MAC scheme及key ceremony；
- backend自行標示`production_ready`已經獨立證實；
- execution scope已由authenticated system configuration發布及驗證；
- clock source具secure time、rollback resistance、reboot continuity或external attestation；
- actual replay／journal object identity已由hardware／OS attestation證明；
- credential具online revocation、anti-replay或single-live-instance enforcement；
- 相同credential不能被兩個process複製；
- scheduler、distributed consensus、stale-call cancellation、physical power-loss或Production-closed。

## 7. 位置與下一步

- Contract／gated runner：`src/pq_sat_auth/v2/reconciliation_context.py`
- Tests：`tests/system/test_pq_sat_auth_reconciliation_context_v2.py`
- Machine claims：
  `manifests/pq_sat_auth_fgs_reconciliation_execution_context_v0_2.json`

下一個production-oriented gate應先選擇並版本化真實credential authority／verification key role、
可信clock source與credential revocation／single-live-instance policy，再建立operator-authenticated
bounded scheduler。若只啟動scheduler卻沒有上述實例化，仍只能是test scheduler。
