# 測試地圖

| 路徑 | 對應機制 |
| --- | --- |
| `tests/system_modules/governance/` | System initialization、issuer authorization、FAC auth、quota |
| `tests/system_modules/opening/` | Opening gate、share、combiner |
| `tests/system_modules/integration/` | `VerifyTicket` 與 opening 等跨模組接合 |
| `tests/system/` | Access V1／V2、wallet、replay、revocation、reconciliation |
| `tests/prototypes/` | Access NIZK 與 holder-signature experimental profiles |
| `tests/threshold_candidates/` | Threshold backend research candidates |
| `tests/test_pq_rbbc_issuance_*` | Offline issuance bounded execution chain |
| 其他 `tests/test_pq_rbbc_*` | PQ-RBBC core、CAP、evidence 與 historical regression |

完整 baseline：

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Optional external artifacts 缺少時可以 skip；failed／errors 與 skipped 必須分開報告。

