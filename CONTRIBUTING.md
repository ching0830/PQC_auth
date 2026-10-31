# 後續維護

日常基準是 `codex/pqsat-buov-thesis-code-v0-1`；本次是獨立 root snapshot。
原研究 branches／worktrees 仍由研究倉庫保存；不合併其大量中間文件到本分支。

1. 一個實作任務使用一個 `codex/` 分支／worktree；程式放現有 versioned package。
2. 保留 frozen profile／relation／CS identity 與 source overlay pins。變更密碼語義須建立新版本；
   不以改 checksum、fake proof 或 test adapter 使 production gate 通過。
3. 跑 `python3 -B release.py test`、`python3 -B release.py compare`、`git diff --check`；
   檢查 `git status --short`，不得提交 artifact、secret、真實 RID、wallet、cache、logs 或私鑰。
4. 更新受影響的 provenance／測試與重現說明。只記錄實際結果，passed／failed／skipped 分列。
5. 審閱 `git diff --stat` 與 staged diff 後正常 commit；只以明確 refspec push 目前任務分支。
   不使用 force push、`--all`、`--mirror` 或自動更動遠端 `main`／default branch。

`provenance/source_inventory.json` 固定初始來源及初始發布 bytes；後續修改來源檔時，
明確更新該 entry 的 publication pin／adapted 記錄與新 commit 的說明，保留 source pin。
外部 inputs 一律先核 size／SHA-256；不得載入下載的 pickle。
