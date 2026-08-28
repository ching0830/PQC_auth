[English](README.md)

# PQ-RBBC 模組

PQ-RBBC 是完整衛星認證論文中的 relation-bound blind-ticket 與 signature-gated trace-opening 密碼學模組。

## 目前路徑

遷移第一階段刻意保留以下歷史路徑：

- implementation：[../../src](../../src)
- tests：[../../tests](../../tests)
- manifests：[../../manifests](../../manifests)
- formal proof：[../../docs/proof](../../docs/proof)
- RBBC roadmaps：[../../docs/roadmaps](../../docs/roadmaps)
- release notes：[../../docs/releases](../../docs/releases)
- artifact documentation：[../../docs/artifacts](../../docs/artifacts)
- portable metadata：[../../artifacts/metadata](../../artifacts/metadata)
- checksums：[../../checksums](../../checksums)

## 對系統暴露的邊界

預定的 system-facing operations：

- setup 與 public-parameter publication；
- 經身分驗證的 relation-bound blind issuance；
- canonical ticket parsing 與 `VerifyTicket`；
- gated `OpenShare`；
- robust threshold combination。

本模組不得暴露可對裸 trace ciphertext 進行 partial decryption 的 production API。目前也沒有獨立的 rerandomizable 或 zero-knowledge presentation protocol；重複出示同一張 ticket 仍可被連結。

## 目前 checkpoint

以 [../../docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md](../../docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md) 作為 authoritative operational handoff。單一 component checkpoint 不代表完整模組或論文系統已封閉。

## 遷移規則

Active tree-producer 工作仍依賴既有路徑時，不得移動或重新命名 RBBC implementation 與 evidence。後續 path migration 必須獨立執行、保留歷史、經機械式驗證，且不得改變 sealed artifact contents 或 digests。
