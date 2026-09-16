# Ticket lifecycle、replay、revocation 與 handover

回答：一張 ticket 何時算消耗？重送、crash、revocation 與 serving-context 變動如何處理？

## 程式

- V1 baseline：`src/pq_sat_auth/replay.py`、`admission.py`
- V2 state：`src/pq_sat_auth/v2/replay.py`、`grant.py`、`activation.py`
- Durable stores：`src/pq_sat_auth/v2/storage/`
- UE recovery：`src/pq_sat_auth/v2/wallet.py`、`ue.py`
- Revocation／reconciliation：`reconciliation*.py` 與 scoped-revocation store

## 已有成果

單主機 SQLite 上的 reserve／consume、response recovery、wallet、delivery、activation inbox、
revocation fence、expired-reservation reconciliation、audit／resume／lease 與 authenticated
execution context 已 Implemented／Tested。

## 尚未完成

跨主機 linearizability、實體斷電 qualification、production key protection、完整 handover
protocol 與 distributed deployment 尚未完成。Strictly one-use claim 只能在明示的 store／
holder-authentication／failure assumptions 下成立。

