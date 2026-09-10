# PQ-RBBC v2.42 bounded recovery 與 provenance

V2.42 修正 Codex AI-assisted review 的 CR-01 中斷恢復缺口與 CR-02 文獻引用歸屬。
新 append-only checkpoint journal 可在驗證 exact orphan 後恢復，並冪等完成 final
checkpoint／index；新 erratum 將 Blind-UOV CAP parameters 指向 2025/895 Table 2、
performance 指向 Table 4，另列 BAVC 與 generic TCitH 來源的 exact PDF revisions。

Historical v2.33 spec、v2.38／39 evidence 與 v2.41 operator reservation 保持原樣。
本 checkpoint 不授權 v2.42 reservation／launch candidate，也沒有獨立人員核准。
所有 production／security claims 維持 false。

變更、設計、完整測試對照與重現命令見
[artifact note](../artifacts/PQ_RBBC_v2_42_RECOVERY_AND_PROVENANCE_zh-TW.md)。
本 branch 只 commit，未 merge／push，等待重審及整合。
