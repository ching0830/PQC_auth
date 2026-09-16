# Conditional opening

回答：在什麼 case／purpose／evidence／expiry 下，哪些 OA 可以共同恢復 RID？

## 程式

- `src/pq_rbbc/opening/request.py`：canonical request。
- `src/pq_rbbc/opening/gate.py`：authorization、expiry、replay 與 policy gate。
- `src/pq_rbbc/opening/shares.py`、`combiner.py`：bounded share／combine boundary。
- `tests/system_modules/integration/test_verify_ticket_opening.py`：`VerifyTicket` 接合。

## 目前邊界

Canonical objects、fail-closed gate 與 test-only combine 已 Implemented／Tested；production OA
threshold encryption、DKG、authenticated share proof、robust decoder與public audit transcript
尚未完成。Opening API 不得暴露任意裸 ciphertext 的 partial decrypt。

