# Offline issuance

UE 在地面端以已認證 RID 取得匿名、可追責 ticket；大型 `R_issue` proof 不進入衛星
online path。

## 主流程

```text
ticket／holder／trace witness
  → R_issue I1–I5
  → CAP split／multi-tree／global tail
  → fresh parent relation
  → qualified PQ-SE backend
  → pi_issue
  → issuer blind response／ticket finalization
```

## 程式

- Reference relation：`src/pq_rbbc_reference.py`、`src/pq_rbbc_issuance_relation_v1.py`
- Bounded execution chain：`src/pq_rbbc_issuance_*_v1.py`
- CAP／Blind-UOV core：`src/pq_rbbc_cap_*`、`src/pq_rbbc_blind_uov_*`
- Current issuance handoff：
  [`../../docs/roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md`](../../docs/roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md)

## 目前邊界

Latest checkpoint 是 fresh parent I1–I5 CandidateSet read-only preflight，仍只使用 bounded
insecure fixture。正式 parent consumer、qualified PQ-SE backend 與正式 `pi_issue` 尚未完成。

