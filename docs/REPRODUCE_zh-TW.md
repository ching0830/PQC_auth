# 安裝、重建與重現邊界

## 不需外部 artifacts 的部分

`python3 -B release.py test` 與 `python3 -B release.py compare` 使用 Python 3.12 stdlib。
前者保留 external-native skips，後者核舊 30 票 summary 與獨立 OA 的每一組十筆統計。
這些不是新的效能樣本或完整 proof replay。

可用 GCC／OpenSSL 開發環境另外建立小型 native controls；不載大 CS、不產生 CAP proof：

```bash
mkdir -m 700 /tmp/pqsat-hplus-public-controls
gcc -O2 -std=c17 -fPIC -shared -fopenmp -Wall -Wextra -Werror -march=x86-64 \
  native/blind_uov_cap_hplus_research_v0_1/opening.c -lcrypto \
  -o /tmp/pqsat-hplus-public-controls/libopening_hplus.so
gcc -O2 -std=c17 -fPIC -shared -fopenmp -Wall -Wextra -Werror -march=x86-64 \
  native/blind_uov_cap_opening_v0_1/opening.c -lcrypto \
  -o /tmp/pqsat-hplus-public-controls/libopening_legacy_control.so
gcc -O2 -std=c17 -fopenmp -Wall -Wextra -Werror -march=x86-64 \
  native/blind_uov_cap_hplus_research_v0_1/input_controls.c -lcrypto \
  -o /tmp/pqsat-hplus-public-controls/input_controls
BUOV_HPLUS_TEST_BUILD=/tmp/pqsat-hplus-public-controls python3 -B release.py test
```

## 完整主方案的精確外部輸入

唯一清單是 `provenance/external_artifacts.json`，逐檔固定 size／SHA-256。
它含 94 個 rlibs、compiler binary／driver／LLVM／target sysroot、public T、
原公開 setup binary／receipt，以及 688,968,080 B 的 public CS cache。
compiler 是 `rustc 1.100.0-nightly (6eeff9a52 2026-09-23)`；必須核 bytes，版本字串不足。
原量測平台是 Linux x86_64、glibc 2.35、GCC 11.4／OpenMP、OpenSSL 3；
需 procfs、memfd seals 與至少原 guard 規定的可用記憶體。system shared libraries 由主機提供。

**尚無公開 artifact 下載 URL。**若未由實驗保存者取得符合清單的可信輸入，
只能執行 source／分析檢查，完整 run 明確不可用。不得任意替代檔案、改 pins 或下載 pickle。
工具鏈與 rlibs 是可執行輸入，SHA 核對不能取代取得來源的信任。

安裝者只需指定這五組來源，不必手選 164 個檔；先只核對，再按需要複製到共用外部目錄：

```bash
PYTHONPATH=src:. python3 -B -m publication.install \
  --toolchain /trusted/toolchain --deps /trusted/release/deps \
  --public-t /trusted/trace.T --setup-build /trusted/setup-build \
  --cache /trusted/public.hplus-cs-cache --check-only

# 同一組引數，改為 --destination /absolute/shared/pqsat-thesis-artifacts-v0-1
```

目標必須是新且位於 source 之外的目錄；installer 先完整核輸入、複製為普通檔、
設定 public cache 唯讀，最後再驗所有目標。可以供多個 source worktree 共用；
每個 run_root 則是獨立可寫 account。工具不複製私鑰、RID、CAP state 或 private witness。

## source 重建資料與尚未解決的資格

本版附上真實 Hχ⁺ C／Rust source、source-coupled 共用核心、完整 target128 Cargo adapter source、
實際 Cargo.lock、9 個基礎研究 patch 加 compact-cache 與 target128 overlay。
上游 source 可從 [Binius64 的固定 commit](https://github.com/binius-zk/binius64/tree/4428e759dd27956bd5b9ae5025d67eb8ccc1accf) 取得：

```bash
git clone https://github.com/binius-zk/binius64.git /absolute/source/binius64
git -C /absolute/source/binius64 checkout --detach 4428e759dd27956bd5b9ae5025d67eb8ccc1accf
PYTHONPATH=src:. python3 -B -m publication.rebuild \
  --upstream /absolute/source/binius64 --output /absolute/new-build-source
```

`rebuild` 只建立新的 fork／adapter，逐步核 patch 本身與每個 base／patched source SHA；
不依賴舊 build receipt、不下載、不編譯、不產生 witness。`source-stage.json` 列出 Cargo 命令。
Cargo 使用 `--locked`，registry archive checksum 由 lock 固定。
編譯時明確設 `CARGO_HOME`、`CARGO_TARGET_DIR` 到外部位置、`RUSTC` 指向上述工具鏈，
`CARGO_BUILD_JOBS=1`、`RAYON_NUM_THREADS=1`，原 RUSTFLAGS 為
`-C target-cpu=native -Z unstable-options --jobs-frontend=1 --jobs-backend=1 -C codegen-units=1`。
這只重建研究 dependency source；**尚未驗證能重建逐 byte 相同的 94 個 rlibs、原 setup binary
及含舊命令路徑的 build receipt。**若產出 identities 不同，安裝與完整 run 會拒絕。
要採用新工具鏈或可攜建置輸出，須另立版本、驗 CS／setup 等價及更新證據，不能默改本版 pins。

## 執行與資源

配置只有 `schema`、`artifacts`、`run_root` 三欄，未知欄位拒絕；不能由配置改 gate 或資源限制。
run_root 保留原 guard 的 `/tmp/pqsat-buov-cap-hplus-*` 命名及一層 account 約束。
`publication/runtime.py` 僅重定位八個 Path 常數及其 captured Path defaults；
source、native、cache、profile、CS、Verify 與資源檢查函式均保留。
bootstrap 套用到每個新角色 interpreter，若失敗即 exit 78；不會靜默用舊路徑。
所有程式以 `release.py` 為使用入口；`benchmarks/` 的原歷史 module defaults 僅供 identity 保存。

```bash
python3 -B release.py doctor --config runtime.local.json
python3 -B release.py run --config runtime.local.json --label thesis-replay-001
```

label 必須全新。run 會先核全部外部 inputs，再由同一共享鎖與 guard 建立新的本地 native lifecycle build、
跑其 native controls，之後執行真實單次發行／驗票與變更 controls。共享鎖是主機的
`/tmp/pqsat-iss-parallel-research-dispatch-v0-1/shared-science-v0-1.lock`，它不是 artifact／舊工作樹依賴。
原停止條件包含 4 GiB sampled tree RSS、8 GiB process AS、CPU 1802 秒、單檔 1 GiB、
account 10 GiB、可用記憶體准入 16 GiB／停止 8 GiB及最多一個重型工作；抽樣非形式 RSS 上界。
首次建置與冷設定另計，不把本版移植檢查冒充新的 benchmark。

公開 proof、statement 與 receipts 留在配置的 account；UE private frame、CAP state、z 不持久化。
不要提交 account、binary、cache、logs 或任何私密資料。原始量測 note 保留歷史路徑與命令作為
provenance；其本機路徑不是本版入口的預設。
