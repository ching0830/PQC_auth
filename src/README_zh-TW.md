# 程式架構地圖

`src/` 目前同時包含穩定 package、歷史相容程式與研究 prototype。不要只按檔名長短判斷
重要性；先按下面三層理解。

## 1. System-facing packages

```text
src/pq_rbbc/
├── contracts/       system configuration contracts
├── governance/      system init、issuer authorization、FAC authentication、quota store
├── opening/         opening request、gate、share、combiner
└── tickets/         stable VerifyTicket adapter

src/pq_sat_auth/
├── access.py ...    V1 historical baseline
├── admission.py     V1 one-time admission checkpoint
└── v2/              current access processors、wallet、stores、reconciliation

src/pq_threshold_candidates/
└── gf/              research-only threshold/GF candidate contracts and evaluators
```

## 2. Evidence-coupled PQ-RBBC modules

根目錄的 `src/pq_rbbc_*.py` 不是理想的新專案 layout，但目前分成三組：

| Prefix | 機制 |
| --- | --- |
| `pq_rbbc_cap_*` | legacy CAP、unified-tree candidate、launch／recovery evidence |
| `pq_rbbc_issuance_*` | `R_issue` bounded execution、split／multi-tree／parent pipeline |
| 其他 `pq_rbbc_*` | field/hash、Blind-UOV ABI、reference relation、parent join |

這些路徑受 historical manifests／tests／external evidence 約束，現階段不移動。新程式若
沒有相容性理由，不應繼續新增無分類的 root module；優先放進 package subdirectory。

## 3. Experimental namespaces

`src/pq_sat_auth/v2/prototypes/` 明確隔離尚未採納的 cryptographic designs：

- `access_nizk/`：exact `R_access` MPCitH proof baseline；
- `holder_auth_v3/`：ML-DSA／FAEST holder-signature handshake candidates。

Prototype 不得被 production registry 默認載入，也不得因 unit tests 通過而升格為
Production-closed。

## 新機制應放哪裡

新 access 機制若正式採用，應建立新的 versioned package，例如 `pq_sat_auth/v3/`，並讓：

1. ticket／`VerifyTicket` 先提供可信 holder descriptor；
2. access parser、holder authentication、AKE transcript 與 state adapter 使用同一版本；
3. V1／V2 imports 繼續可用，直到 migration tests 與 deprecation policy 完成。

不要直接把 V2 的 `access_nizk` 欄位改名成 signature，也不要在同一 version 靜默改變
`attempt_id`、transcript 或 ticket payload 語意。

