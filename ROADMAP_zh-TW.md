[English](ROADMAP.md)

# 論文研究 Roadmap

這是專案級 roadmap；各模組內部 checkpoint 仍以其 module-specific roadmap 為準。

## 工作線

| Track | 目標 | 相依項目 | 現在可進行？ |
| --- | --- | --- | --- |
| T0 — 架構與 claims | 固定角色、階段、介面、threat model 與 claim vocabulary | 無 | 進行中 |
| T1 — PQ-RBBC core | 完成 production composition、parent join、fork proof、backend 與 benchmarks | 既有 RBBC artifacts | 可以；目前 tree 工作 |
| T2 — Federation authorization | 定義 FAC threshold issuer／configuration authorization 與 evidence format | T0 | 可以 |
| T3 — Opening governance | 定義 case authorization、OA gate、robust shares、combine 與 public audit evidence | T0；穩定 RBBC ticket digest | 可以 |
| T4 — Satellite access 與 PQ AKE | draft access codecs 與 transcript identities 已建立；選定 holder authenticator／PQ AKE，並定義 UE–FGS state machine、LEO／FLEO 角色與 session keys | T0；穩定 VerifyTicket interface | 可以 |
| T5 — Replay 與 lifecycle | v0.1 draft 與 test-only state model 已建立；review 並 freeze production store、suite、revocation、expiry 與 recovery interfaces | T0；T4 interfaces | 可以 |
| T6 — Handover | 定義 serving-context transition 與 continuous authentication | T4；T5 | 可先做 specification |
| T7 — Security proof composition | 將各模組 games 組合成 end-to-end theorems | 穩定 T1–T6 semantics | 稍後 |
| T8 — Evaluation | communication、computation、storage、latency、throughput、jitter 與 baselines | executable modules | 可先做 instrumentation |
| T9 — Paper integration | system model、proposed scheme、proofs、evaluation 與 limitations | 全部 tracks | 可逐步進行 |

## 近期平行計畫

### Lane A — 既有 RBBC 工作

依 [docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md](docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md) 繼續。目前架構重整期間不得變更 tree-producer paths 或 artifact identities。

### Lane B — System specification

1. 將已選定的 short-lived、strictly one-use ticket policy 固定為 exact state-transition specification；unlinkable presentation 保留為未來擴充。
2. 固定 UE、HNCC、FAC、OA、FGS、FLEO／LEO 與 Operator API。
3. 固定 access 與 opening transcripts。
4. 撰寫 end-to-end threat model 與 security games。
5. 加入 machine-readable protocol schemas 與 cross-module conformance tests。

### Lane C — RBBC 以外的實作

低衝突起點包括：

- canonical system／context encodings；
- FAC authorization objects 與 verification interface；
- opening-request 與 opening-evidence schemas；
- replay-state reference implementation；
- UE–FGS transcript state machine；
- communication-size accounting；
- 使用 stubbed RBBC adapter 的 end-to-end test vectors。

這些工作不需要修改 RBBC tree producer。

## Integration gates

- **G0 Architecture freeze：**固定角色、階段、trust、ticket-use semantics 與 module ownership。
- **G1 Interface freeze：**固定 canonical encodings 與 API。
- **G2 Module closure：**各模組完成 positive、negative、mutation、replay tests，並維持保守 claims。
- **G3 Cross-module closure：**issuance、authentication、opening、audit 之間使用同一份 bytes，不得重新解讀。
- **G4 End-to-end security：**完成組合 games 與 reductions review。
- **G5 Satellite evaluation：**量測 online communication 與 LEO／FGS computation。
- **G6 Paper-ready closure：**claims、implementation、evidence 與 manuscript 一致。

## Repository 遷移

第一階段保留 RBBC 既有路徑，同時加入 project-level docs 與 module ownership。第二階段只有在 active long-running RBBC branches 已 merge 或 rebase 後，才考慮將 RBBC source、tests、manifests、artifacts 與 proof history 搬入專屬 module layout。任何搬移都必須保留歷史及精確 artifact identities。
