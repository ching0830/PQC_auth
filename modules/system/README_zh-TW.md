# System initialization 與 Issuer authorization

回答兩個問題：整個 federation 信任哪份 configuration？HNCC 在什麼 epoch／policy／quota
下可以發票？

## 程式

- `src/pq_rbbc/contracts/system.py`：configuration／public initialization contracts。
- `src/pq_rbbc/governance/system_init.py`：initialization validation。
- `src/pq_rbbc/governance/issuer_authorization.py`：issuer grant 與 quota semantics。
- `src/pq_rbbc/governance/storage/sqlite_quota.py`：單主機、多程序、restart-safe quota store。
- `src/pq_rbbc/governance/authentication/`：ML-DSA-65 staging authentication boundary。

## 目前邊界

S0／S1 storage 已 Implemented／Tested；S2 有 non-threshold ML-DSA staging adapter。真實
FAC threshold authentication、DKG、跨主機一致性與完整 production initialization 尚未完成。

詳細證據：`docs/artifacts/system_governance/`；測試：
`tests/system_modules/governance/`。

