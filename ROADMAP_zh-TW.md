[English](ROADMAP.md)

# 論文研究 Roadmap

這是專案級 roadmap；各模組內部 checkpoint 仍以其 module-specific roadmap 為準。

## 工作線

| Track | 目標 | 相依項目 | 現在可進行？ |
| --- | --- | --- | --- |
| T0 — 架構與 claims | 固定角色、階段、介面、threat model 與 claim vocabulary | 無 | 進行中 |
| T1 — PQ-RBBC core／issuance | CAP線至v2.43 reservation binding；issuance線至bounded fresh-parent CandidateSet preflight | human review；fresh-parent consumer；qualified PQ-SE | CAP human-review gate暫停；issuance可進exact review與下一個bounded consumer |
| T2 — Federation authorization | S0/S1 persistent quota與S2 ML-DSA staging已有bounded implementation | production FAC threshold primitive／DKG／distributed quota | 可以；先凍結FAC threshold contract |
| T3 — Opening governance | canonical gate／share／combine及stable `VerifyTicket` integration已測試 | production OA threshold backend／DKG／share proof | 可以；先完成backend selection與robust transcript |
| T4 — Satellite access 與 PQ AKE | V2完整reference pipeline存在；exact NIZK、D4 ML-DSA與D4b FAEST為三條可比較線 | D5 `R_key`、new ticket／`R_issue`、production PQ suite | 可以；整理後先做D5，再決定新version |
| T5 — Replay 與 lifecycle | V2單主機SQLite wallet／replay／revocation／reconciliation已測試 | T4新version adapter、跨主機linearizability、power-loss qualification | 可以；先保持state core與crypto profile解耦 |
| T6 — Handover | 定義 serving-context transition 與 continuous authentication | T4；T5 | 可先做 specification |
| T7 — Security proof composition | 將各模組 games 組合成 end-to-end theorems | 穩定 T1–T6 semantics | 稍後 |
| T8 — Evaluation | communication、computation、storage、latency、throughput、jitter 與 baselines | executable modules | access三線已有prototype數據；production ticket仍待完成 |
| T9 — Paper integration | system model、proposed scheme、proofs、evaluation 與 limitations | 全部 tracks | 可逐步進行 |

## 近期平行計畫

### Lane A — 既有 RBBC 工作

CAP線依 [docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md](docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md)
繼續。V2.43已建立owner-controlled reservation，但使用者目前找不到合格且identifier不同的
具名獨立human reviewer，因此停在review gate；不得建立launch manifest或啟動production。

Issuance線另依
[docs/roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md](docs/roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md)
繼續；先重審`b877189`，再實作bounded fresh-parent relation consumer。兩條線不得再共同
覆寫同一份current handoff。

### Lane B — Access mechanism migration

1. 保留V1、V2與exact `R_access` prototype作baseline，不就地改義。
2. 先做D5 `R_key` circuit cost，選擇ML-DSA或FAEST holder profile。
3. 將使用者提供的`ctx`統一公式候選做construction review，凍結`R_issue,new`、ticket、
   holder signing input、AKE transcript與retry identities。
4. 以新version package實作，不修改V2 production registry。
5. 完成cross-version consumption、migration與security-composition tests後才討論deprecation。

### Lane C — System／opening／lifecycle

可平行進行：

- canonical system／context encodings；
- FAC authorization objects 與 verification interface；
- opening-request 與 opening-evidence schemas；
- FAC threshold primitive contract與OA backend research；
- distributed replay-state contract；
- handover transcript state machine；
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

第一階段已建立`START_HERE_zh-TW.md`、七個mechanism entry pages、source／test maps與
machine-testable module registry，並在整合候選中集中主要完成成果。Evidence-coupled
`pq_rbbc_*.py`、historical docs、tests與manifests暫不搬動。

第二階段要等新access機制定案，再把新程式放進versioned package；舊V1／V2與RBBC歷史
路徑只透過compatibility imports或明確archive index逐步收起。任何實體搬移都必須是獨立
checkpoint，並驗證imports、tests、links、checksums與external review references。
