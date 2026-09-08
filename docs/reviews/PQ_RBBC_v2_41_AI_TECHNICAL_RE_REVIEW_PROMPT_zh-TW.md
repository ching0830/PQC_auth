# PQ-RBBC v2.41 AI technical re-review prompt

請在 `codex/pq-rbbc-v2-41-launch-validation-hardening` corrective commit 的獨立乾淨
worktree 執行唯讀、AI-assisted technical re-review。先核對
`git status --short --branch`、HEAD、main 與 worktree list；不要切換或修改其他 task。
Corrective HEAD 必須是 `1b89ebea12110a655dc1dc6abb5a00d4bd38a338` 的直接後繼，且
尚未 merge/push；請記錄實際 corrective commit hash，不要只由文件推測。

本審查不是 external human cryptographic review、independent-review attestation、
operator approval、launch artifact、identity freeze 或 execution authorization。

先完整閱讀：

1. `AGENTS.md` 及其指定的相關研究／文件政策、architecture/status/handoff、artifact policy。
2. `docs/artifacts/PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md`、
   `docs/artifacts/PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md`、
   `docs/artifacts/PQ_RBBC_v2_41_LAUNCH_VALIDATION_HARDENING_zh-TW.md`。
3. 三份 v2.41 source：`pq_rbbc_launch_io_v2_41.py`、
   `pq_rbbc_cap_unified_tree_launch_validation_v2_41.py`、
   `pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41.py`。
4. 新的兩份 tests、三份 schemas、transition manifest、checksum inventory、
   `artifacts/metadata/cap_unified_tree_launch_validation_v2_41/` 下所有 JSON。
5. V2.38/v2.39 historical implementation、tests、schemas、manifests、portable evidence。
6. 若本機仍有原始預審目錄，讀取
   `/tmp/pq-rbbc-v239-ai-prereview-61qzZGSw/AI_TECHNICAL_PRE_REVIEW_zh-TW.md`、
   `probe-results.json` 與 `probes.py`。不要執行會回寫原 probe-results 的舊 probe；
   可在新的 `/tmp` 目錄撰寫等價 synthetic regression。
7. 若本機仍有 commit `1b89ebe` 的重審目錄，讀取其
   `AI_TECHNICAL_RE_REVIEW_zh-TW.md`、`inplace_probe.py` 與
   `inplace-results.json`；將 probe 複製到新的 `/tmp` 目錄後執行，避免覆寫原結果。

請獨立核對下列八項，不因 tests 已通過就假設修正充分：

1. 依 corrective contract 核對每份 candidate 是否只 single-open、single bounded read
   一次；identity、strict JSON decode／canonical parse、binding 與所有 semantic validation
   是否始終來自同一 immutable `Snapshot.raw`；builder/sealer 是否還有分離的 hash/parse
   pathname 讀取。不得要求 inode／size／mtime／ctime 證明 capture 期間沒有 writer；它們
   只能作 best-effort mutation signals。執行受控同 inode、同長度原地改寫 regression：
   若舊 bytes 已完整 capture，可以接受該舊 snapshot，但 identity、parse 與 binding 必須
   全對應同一 raw，pathname 後續內容不得取代它。另核對 detectable inode replacement、
   rename、symlink、FIFO、oversized/deep JSON 拒絕仍成立。
2. 驗證的三份 exact absolute locations 是否就是 command inputs；same-basename
   substitution、root alias、parent rename、command digest 重算、explicit rebind 是否
   需要重新綁定 reservation/review/launch。確認沒有 self-referential launch digest。
3. Duplicate keys、UTF-8/BOM、NaN/Infinity、decimal/exponent、alternate escapes、
   key order、newline/trailing bytes、unpaired surrogate 是否都按 encoding contract
   拒絕，且 `raw == canonical_json(parsed)`。
4. 所有 boolean 是否 exact bool；integer 是否拒絕 bool/float；nested identities 是否
   共用 strict grammar。逐層 unknown-field、missing-field、錯型別 mutation 是否受控拒絕，
   包含 `method=[]`。區分 JSON Schema 的 mathematical integer 與額外 byte grammar。
5. Trusted now 的来源、取樣時機及注入方式；window start/expiry、approval/review/launch
   時序；直接提供過早 launch、過期/未生效 reservation、slow read、驗證後跨 expiry
   是否拒絕；啟動前是否重新檢查相同 snapshots 與新時間，且 production 仍無條件拒絕。
6. Review subject 是否綁定 exact reservation bytes/length/SHA、reservation ID、batch、
   command；修改窗口/CPU/RAM/reference 或混批是否必須取得新的 review。確認 self-declared
   authenticity/independence 仍不是驗證過的人員資格或 detached signature。
7. 所有新增 output paths 是否經 exclusive atomic publication；existing/dangling
   symlink、concurrent writer、parent substitution、failure-before-publication 是否避免
   overwrite/partial final。核對明確 artifact root、ownership/modes、Git worktree
   排除及 user-namespace `/` owner trust anchor 的適用限制；指出 trusted-root owner
   可控制同 UID 行為時的威脅模型界線。
8. Preflight authoring gate、直接 builder、CLI author 與 evidence builder 是否都要求
   exact tracked contracts 與 exact v2.38 predecessor；缺件、byte mutation 或 TOCTOU
   不得使 authoring readiness 與 read-only gate 互相矛盾。

另確認 future executor contract 仍要求直接消費 `CandidateSet` 內已驗證的相同
snapshots，不得重新開啟 candidate pathname。將 trusted producer handoff、writer
quiescence、owner／mode／ACL、既有 writable FD 與 mount namespace 列為部署前提／外部
blocker。不要以增加 stat 次數、sleep、重讀 pathname、比較第二次內容或 advisory lock
宣稱一般 filesystem 上的強不可變性保證。

重新執行（全部使用 `PYTHONDONTWRITEBYTECODE=1`）：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_cap_unified_tree_launch_preflight \
  tests.test_pq_rbbc_cap_unified_tree_launch_preflight_evidence \
  tests.test_pq_rbbc_cap_unified_tree_launch_validation_v2_41 \
  tests.test_pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41 -v

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

核對全部 19 份 historical identities、v2.39 manifest/portable/checksums 未改寫，及新
portable 的 deterministic negative-report rebuild。不要要求 current handoff/status
符合舊 historical inventories；依 artifact note 的 commit-qualified docs mapping 驗證。

禁止修改任何 repository source、manifest、portable evidence、checksums/status；禁止
填寫真實 reservation、偽造 review、產生正式 identity freeze；禁止 production-prefreeze、
large replay 或 proving。Unit tests 的 synthetic fixtures 與 bounded refusal probes
可執行；不建立或啟動可用的 production artifact set。

請將報告/probe 程式/results 只寫入新的 `/tmp/pq-rbbc-v241-ai-rereview-*` 目錄。
每項 finding 提供 priority、精確 file/line、trigger、observed vs expected behavior、
最小重現、對現有邊界的影響與具體建議；沒有 finding 時也列出剩餘風險、未驗證項目、
passed/failed/errors/skipped counts。完成前再核對 Git 狀態。不得 commit、merge 或 push。

所有 production/security claims 必須保持 false。審查結果只作為後續工程與正式獨立
審查的技術依據，不作為 approval 或 execution artifact。
