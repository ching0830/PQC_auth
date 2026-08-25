# PQ-RBBC / SGTD v1.6 研究檢查點

## 本版完成

- 修正 Blind-UOV signer-view ABI：issuance 公開 request 僅含 `y_0 || y_1`（64 bytes）。
- `m`、`r_i`、`rho_i` 與 `c_r,i` 全部留在 `pi_issue` witness；`c_r,i` 不在 issuance request 中，避免 issuer 直接連結 final signature。
- 加入兩條獨立、domain-separated Blind-UOV-Is lane。每條 lane 簽署
  `mu_i = Encode("PQ-RBBC/BUOV-LANE", i, m)`，共同綁定同一 ticket digest `m`。
- 把原先不成立的「CAP binding + hash collision 即推出 message uniqueness」改為明示的 dual-lane cross-message claw 假設。
- 更新 reference relation、負向測試、binary F2-R1CS 封存器與條件式安全證明。

## 固定結果

- Issuance request（不含 proof）：64 bytes。
- Ticket payload：368 bytes。
- Final signatures：2 x 3,772 = 7,544 bytes。
- Online ticket：7,912 bytes。
- 共享增量電路：684,419 nonlinear constraints。
- Portable F2-R1CS：2,968,700 rows、2,976,784 wires。
- Public input：3,968 bits；secret input：7,072 bits。
- Native Blind-UOV external assertions：2（尚未封閉，不能當 production proof）。
- 封存 SHA-256：`127d6081e8c52c0adfd0441639fb7c53c803be43944f2230a8cbf91d18150892`。

## 驗證結果

- ABI / primitive / relation 測試：14 項通過（含 8 種 full-circuit mutation）。
- Backend 測試：5 項通過；全 2,968,700 rows round-trip 成功。
- Assignment bit tamper 與 archive corruption 均被拒絕。
- PDF：22 頁，兩次 LaTeX 編譯後無 unresolved reference、citation 或 overfull box；已完成全頁渲染抽查。

## 尚未完成（不得誤稱正式安全）

1. 為 structured `J^0,J^1` map 完成 QROM dual-claw reduction，或換成已有正式定理的 combiner。
2. 把兩個 external assertion 換成 Blind-UOV 原生 TCitH/Anemoi `pi_1` / CAP constraints。
3. 選定並證明 post-quantum ZK + simulation-extractable backend；證明 affine elimination sound。
4. 匯入真正 Goppa key、threshold decoder 與 robust share transcript。
5. 重新評估 2026 McEliece cryptanalysis 對 threshold trace layer 的影響。

## 重跑

```bash
python -m unittest -v test_pq_rbbc_blind_uov_abi.py test_pq_rbbc_reference.py
python -m unittest -v test_pq_rbbc_br1cs.py
python pq_rbbc_blind_uov_abi.py > pq_rbbc_blind_uov_abi_manifest_v1_6.json
python pq_rbbc_reference.py --full-negative > pq_rbbc_reference_manifest_v1_6.json
python pq_rbbc_br1cs.py pq_rbbc_incremental_v1_6.br1cs > pq_rbbc_br1cs_manifest_v1_6.json
pdflatex -interaction=nonstopmode -halt-on-error -jobname=pq_rbbc_sgtd_core_proof_v1_6 pq_rbbc_sgtd_core_proof_v1.tex
```
