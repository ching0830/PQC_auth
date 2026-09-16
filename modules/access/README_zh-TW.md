# Satellite access 與 PQ AKE

回答：UE 如何在不公開 RID 的情況下，證明自己可使用 ticket，並與指定 FGS 建立 session？

## 三條版本線

| 版本 | 位置 | 角色 |
| --- | --- | --- |
| V1 | `src/pq_sat_auth/access.py` | 四訊息歷史 baseline |
| V2 | `src/pq_sat_auth/v2/` | exact `R_access` NIZK reference 與完整 state pipeline |
| V3 prototype | `src/pq_sat_auth/v2/prototypes/holder_auth_v3/` | holder signature 候選，不是 shared protocol |

V2 specification：
[`../../docs/specs/SATELLITE_ACCESS_v0_2_zh-TW.md`](../../docs/specs/SATELLITE_ACCESS_v0_2_zh-TW.md)。

## 已有成果

- V2 canonical request／accept／activation objects；
- stable `VerifyTicket` adapter、configuration／time／revocation／channel-binding pure checks；
- grant、UE accept、PQ KEM／FGS-auth／Finished abstraction；
- D4 ML-DSA 與 D4b FAEST 真實 signature／ML-KEM wire prototypes；
- exact `R_access` proof-size baseline。

## 尚未決定

目前還沒有決定 V2 exact NIZK 或 V3 holder signature 哪一條成為新正式機制。你提供的
`ctx` 統一公式文件屬於 V3 候選設計輸入；要在 D5 `R_key` 成本與 security composition
完成後才可採納。Production PQ suite、正式 ticket fork 與 security proof 仍未封閉。

