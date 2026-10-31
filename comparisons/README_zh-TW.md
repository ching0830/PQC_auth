# 論文的獨立比較組

`old30/raw_samples.json` 是原 30 筆公開測量紀錄，原 bytes／SHA-256 保持。
`old30/statistics.py` 與 `results.py` 保留原統計／整數時間及 byte 帳目，
僅把 statistics 的 import 改為此處發布路徑；Hyndman–Fan type 7、全部嘗試及慢樣本均保留。
`old30/summary.json` 是原統計，重算需逐欄完全一致。
原公開紀錄的 RID 是 producer 以 `os.urandom(32)` 建立的固定研究 fixture，
30 筆均明列 `research_fixture_not_authentication_session=true`；未使用真人身分或真實 RID。
來源 pin 與生成語句見 `old30/fixture_origin.json`。

`opening/results.json` 保留原獨立 OA 結果與 source identities。每個 timing series 的
10 筆樣本重新核 count／mean／median／min／max／nearest-rank p95；warm-up 1 不入統計。
其中內部解碼通訊為格式推導估計，非多主機網路量測；門檻隱私、DKG、malicious security
與 production qualification 仍未完成。

執行 `python3 -B release.py compare`。此入口只重算公開數值，不呼叫 keygen／Prove／Verify／Access／Open。
producer source commit/path/hash 保存在 provenance/source_inventory.json；那些歷史 commit 不在
此 orphan 分支的祖先中，也不作本入口的執行依賴。舊 cryptographic runtime 未收錄，
因此本版不能獨立重產這兩組密碼學樣本；分析是自足的。

這兩組不共用主體 Hχ⁺ 發行關係、配置、核數與終點，不能組成主方案的端到端樣本，
不能把相除時間當等安全加速比。主體 n=1 原量測另在 manifests/buov_cap_hplus_research_v0_1/lifecycle.json。
