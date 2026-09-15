# PQ-RBBC issuance Global-B CandidateSet preflight 唯讀 re-review prompt

請在新的獨立、乾淨worktree，唯讀審查呼叫者提供的完整exact target commit SHA。Target的直接
parent必須是Global-A serial gate：

```text
278cdf4682b08b18afe83f63fcd51d660a5785b7
```

Target branch應為`codex/pq-rbbc-issuance-global-b-candidateset-preflight-v1`。不要修改repository、
commit、merge、push，也不要執行Global-B、production、large replay或proving。

## 必查 contract

1. Predecessor pins必須精確指向Global-A 1.1與scheduler 1.2 finding-free successor identities。
2. CandidateSet必須同時綁定Global-A complete、scheduler complete、ordered tree results `[0,1]`、
   continuations、points、tree-pre results、adapter prefix/suffix與8筆relocation candidates。
3. Ordinal 2的prefix/suffix filenames不同；判定overlap必須使用相同raw bytes、bytes及SHA-256，
   不能要求pathname名稱相同，也不能只看未驗證metadata。
4. Adapter ordinal 0→3、independent Global-A receipt與兩份tree-post receipts構成分支圖；不得宣稱
   完整線性execution chain。`full_execution_receipt_chain_verified=false`必須全域一致。
5. 八筆relocation sources／targets／widths／packed values必須逐項對應shared inputs、tree-pre results
   與ordered tree-post results；host binding不能冒充native equality replay。
6. Validator只能消費CandidateSet中已capture的immutable raws，不得重開pathnames、重建monolithic
   reference、重跑Global-A/tree-post或發出Global-B constraints。
7. `unified_path_capture_api_implemented=false`。Future capture必須single-open、single bounded read；
   trusted handoff、writer quiescence、permissions／ACL、writable FDs及mount controls仍為外部前提。
8. Global-B consumer、35,494 constraints、native relocation rows、publication/restart、legacy18、
   production、formal `pi_issue`、PQ-SE、large-run、Proof/Production closure必須全部維持false。

## Independent probes

不要只重跑作者tests。至少在`/tmp`建立probe：

- 對8筆relocation逐項做re-pinned source/target/value/version/domain/claim mutation、swap、gap、
  duplicate key及trailing bytes，確認在compute/output前拒絕。
- 對ordinal 2 prefix/suffix raw overlap、ordinal 2→3 link、兩份tree-post branches、points與ordered
  results做re-pinned mutation，確認fail closed。
- Capture合法CandidateSet後改寫所有可用pathname，確認validator仍只消費captured raws；以mock或
  syscall probe確認沒有pathname reopen。
- 在fresh process清除memoized reference後執行validator，確認不建立reference relation、不發出
  rows、不建立output。
- 核對32個snapshot identity roles、7,826 relocation target bits，以及portable evidence不含
  private raws、absolute paths、assignment或checkpoint bodies。

## Commands與交付

至少執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_global_b_candidateset_preflight_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
git diff <exact-parent> <exact-target> --check
```

逐檔核對19份v2.38/v2.39 historical identities，執行prohibited-artifact inventory。交付繁體中文
report、`findings.json`、independent probe source/results、commands/results與SHA-256 inventory；
finding-free結論必須綁定exact commit並列出未驗證範圍。
