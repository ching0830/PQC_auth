# PQ-RBBC v2.41 launch validation hardening checkpoint

本 checkpoint 針對 v2.39 AI technical pre-review 的八項 launch-validation findings 建立：
單次 bounded snapshot、exact command locations、canonical JSON、strict bool/int、
trusted time、reservation-bound review、exclusive output 與 authoring predecessor gate。
V2.39 source/contracts/evidence/checksums 全數保留，新功能使用獨立 v2.41 paths。

Commit `1b89ebe` 的 AI technical re-review 後續指出 P2：inode／size／mtime／ctime
只能作 best-effort mutation signals，不能證明 capture 期間完全沒有 writer。Corrective
contract 現限定為 single-open／single bounded read，identity、parse、binding 與 validation
全部使用同一 immutable `Snapshot.raw`；未來 executor 不得重開 candidate pathname。

實作、設計理由、finding/test 對照、命令與限制見
`docs/artifacts/PQ_RBBC_v2_41_LAUNCH_VALIDATION_HARDENING_zh-TW.md`；完整結果見
`artifacts/metadata/cap_unified_tree_launch_validation_v2_41/pq_rbbc_cap_unified_tree_launch_validation_regression_results_v2_41.json`。

Corrective targeted：69 passed、0 failed、0 errors、0 skipped（2.092 s）。
預審 27 項 probes 對應的 17 項等價回歸：17 passed、0 skipped（0.555 s）。
Corrective full suite：641 tests，629 passed、0 failed、0 errors、12 skipped（711.966 s），exit 0。
12 項 skip 均為既有 optional v2.13–v2.25 external artifacts 未安裝。

沒有真實 reservation/review、正式 launch identity freeze 或任何 production execution。
Production-prefreeze、large replay/proving、CAP/fork security 與 production closure 全部
維持 false。這是等待整合的 branch checkpoint；只 commit，不 merge、不 push。
