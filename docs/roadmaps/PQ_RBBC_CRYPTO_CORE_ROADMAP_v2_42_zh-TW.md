# PQ-RBBC v2.42 roadmap snapshot

V2.42 engineering checkpoint 實作 CR-01 recovery successor 與 CR-02 provenance
erratum。詳細結果由 [artifact note](../artifacts/PQ_RBBC_v2_42_RECOVERY_AND_PROVENANCE_zh-TW.md)
及新 machine evidence 約束，不以測試取代 cryptographic proof。

後續 gates 的順序：

1. 核對 final commit／effective source identities，完成 targeted、full repository
   regression 及獨立 technical re-review；新 blocking findings 必須先修正。
2. 重新取得綁定該 exact v2.42 effective tree、batch、exact command 與可信 artifact root
   的 operator resource reservation。V2.41 原件只保存被拒流程，不能移轉授權。
3. 取得真正具名、具資格且獨立的人員 review；綁定 reservation 的 exact bytes、length、
   SHA-256、reservation ID、batch、command 與受審 implementation commit／source identities。
4. 只有真正 independent review 沒有 blocking findings，才可生成 launch manifest
   candidate。AI-assisted review 或結構合法 JSON 不能替代 reviewer authenticity／independence。
5. 正式 launch identity freeze、可信 producer handoff、execution authorization、production
   runner／relation scale qualification，以及新的 production pre-freeze／two-pass replay
   仍是後續工作。本 checkpoint 沒有可執行的 production command。

CAP acceptance／extractor／unique-mask proof、PoW 完整 accounting、concrete Anemoi
ROM／QROM、fork proof／backend 與 production closure 全部仍未封閉。
