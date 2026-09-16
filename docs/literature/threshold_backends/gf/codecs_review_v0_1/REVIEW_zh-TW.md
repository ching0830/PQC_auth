# GF research codecs v0.1 同作者技術複核

日期：2026-09-14。Branch：`codex/threshold-gf-codecs-review-v0-1`。
被審 commit：`8782d8ccd6bd77b52dd1b54d69fc1ff37d53a048`；tree：
`5819d211a718f15759c4b34cb22e2c18d2e00393`。

**本次範圍內未發現可重現缺陷，沒有修改 runtime、既有 tests 或 frozen ABI。**
新增可重跑的格式差異檢查與 key／pp 輸入混搭實驗，以及對應來源／驗證摘要。
這是同作者技術複核，並非外部獨立審查、完整安全審計或密碼學證明。

## 審查依據與方法

核對 [實作說明](../research_codecs_v0_1/IMPLEMENTATION_zh-TW.md)、
[frozen ABI](../abi_v0_1/SPEC_zh-TW.md)、
[A01–A24 驗收義務](../abi_v0_1/ACCEPTANCE_zh-TW.md)、codecs／bindings 原始碼，以及
它們實際呼叫的 canonical SystemInitializationBundle 與 TB2 public-key parser。
19 份 canonical／研究政策檔、5 份原始附件、10 份被審實作來源及 13 份補充來源的 bytes／
SHA-256 均吻合先前索引。附件仍只作研究輸入；本輪沒有重新核對論文公式或新增
paper-verified／publisher byte-equivalence 宣稱。

逐項檢視型別與長度、固定 header、巢狀 packet、CAP padding、完整 record／pp hash 範圍、
configuration／ctx／epoch／角色、公鑰與 opaque inputs 的比對，以及 production 拒絕順序。
沒有找到把 parser、caller-selected pin 或 artifact hash 誤當 authentication 的成功路徑。
成功結果仍是非 boolean 的 research diagnostic，不能據此推論 trusted acceptance。

新增的 [check_review_v0_1.py](check_review_v0_1.py) 使用不同表示方式檢查格式：

1. 從凍結 JSON 展開 fixed-bit masks 與 nonzero ranges；不讀 runtime `_FIELDS`、`_MAGIC`
   或 `_SIZE`，也不呼叫 runtime encoder 產生初始 packets。
2. CAP rho 的 mask 由文件 grammar 另行推導：84-byte magic/profile、兩個 25-byte salts、
   u16le tree count、36 個 25-byte roots；每個 field element 小於 2^193。
   不呼叫 CAP serializer 或展開 commitment。
3. 對每個 byte 翻轉每個 bit；分別檢查合法變異仍 round-trip，以及固定 bit 變異被拒絕。
   每個 nonzero range 的初始值至少有兩個 set bits，因此單 bit flip 不會意外把它清零。
   再單獨檢查全零拒絕，以及僅有一個 set bit 的 32-byte digest 全部允許。
4. 以整個 little-endian 整數移位建立公鑰 payload，在 9 個係數位置檢查
   0、2094080、q−1、q、2^22−1，涵蓋 packing phase、polynomial／matrix 邊界與最後一項。
   此處的 canonical 人工公鑰不被視為合法 KeyGen 證書。
5. 建立兩組每個輸入群組都不同的 unsigned research graph，枚舉 8 個群組的 256 種混搭。
   Bundle 與其 research pin 算一組，其餘為 pp、key record、三份 opaque inputs、statement、M。
   兩組全一致輸入可回傳 diagnostic；254 種混搭必須拒絕。每種組合另驗 default 與 explicit
   production 均拒絕。

混搭實驗為了走到內層檢查，允許選擇成對的 bundle／pin；這是測試控制，不是信任來源。
兩組輸入共用既有 test fixture helpers、canonical system builders、reference KeyGen 及 Python
hashlib。第二組沿用第一組 C 但改 ctx，刻意不聲稱滿足 I5。格式 oracle 是另一套表示方式，
整個實驗仍是同作者、部分共用依賴的有限測試，不能標為獨立 implementation 或 upstream KAT。

## 結果

| 複核項目 | 結果 |
| --- | --- |
| 5 種 packet 的單 bit 變異 | 67,072 個；62,374 個 canonical 變異 round-trip，4,698 個拒絕，與 oracle 無差異 |
| Nonzero digest 邊界 | 17 個全零欄位拒絕；4,352 個僅一 bit 非零的 digest 接受 |
| 公鑰係數邊界 | 27 個 canonical cases 接受，18 個超界 cases 拒絕 |
| 256 種 key／pp graph 組合 | 2 組全一致輸入僅回傳 diagnostic；254 組混搭拒絕 |
| Default／explicit production | 512 次皆以 Unsupported 拒絕 |
| Threshold targeted regression | 90 passed、0 failed/errors、0 skipped；12.674 s |
| Frozen document checker | 5 structural positives、40 negatives；輸出 digest 與前輪相同 |

複核實驗耗時 3.688 s；計數是有限輸入測試，不是安全性強度或 benchmark。
接受 canonical 變異只代表格式合法，並不代表變異後的 C、witness、key 或 evidence 具有
密碼學有效性。實驗輸出只有計數與狀態，不包含 keys、M、rho、u 或 holder key。

重跑命令（repository root）：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests python docs/literature/threshold_backends/gf/codecs_review_v0_1/check_review_v0_1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/abi_v0_1/check_spec_v0_1.py
git diff --check
```

本輪沒有重跑 full regression：被審 `src/` 與 `tests/` bytes 保持不變，新增複核程式放在
本文件目錄，以獨立命令執行。引用的既有 full baseline 是被審 commit 的 **766 passed、
0 failed/errors、12 skipped，共 778 項，759.285 s**；它不是本輪新執行的結果。
12 個 skips 都是當時缺少 optional external artifacts。原 baseline log identity 另行重核，
不因此宣稱已在本 worktree 執行完整測試。

## Findings 與尚未封閉的邊界

本次新增 actionable findings 為 0。先前 [GFR-01](../review/REVIEW_zh-TW.md) 的跨 key
反例仍有效；本輪 targeted regression 再次檢查 research key mismatch 拒絕，沒有把 I5
或成功解密提升成可信 key identity。

下列事項是原本已明示、且本次未封閉的接合義務：

- 外部 research pin 的真實來源、設定簽章 authentication、key-origin／DKG evidence。
- Opaque backend PP／relation manifest 的 schema、qualification 與完整 I1–I5 constraints。
- Witness-free VerifyIssue、3005-byte M 的 trusted ticket／opening adapters。
- 多輪 threshold transcript、shares、robustness 與 TB3 cryptography。

因此下一步仍是讓 common／B／system owners 定義並接納上述 adapter 契約；本次未代填其
acceptance，也未修改其他工作線。Root methodology、experiments、RESEARCH_STATUS 仍由
integration owner 管理；本文件提供方法、命令／結果及 claim 邊界供其整合。

精確來源 revisions／bytes／SHA-256 見 [來源索引](source_index_v0_1.json)；
本輪輸出 digest、被引用 baseline、範圍不變檢查與 claims 見
[驗證摘要](validation_summary_v0_1.json)。Raw logs、下載資料、PDF、大型附件與任何秘密
輸入均不加入 Git。
