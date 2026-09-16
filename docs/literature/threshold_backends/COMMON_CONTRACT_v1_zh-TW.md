# TB1 共同研究契約 v1

此契約實作於 `src/pq_threshold_candidates/`。它建立候選比較、codec 與拒絕介面，
不凍結 production cryptographic profile，也不改動 canonical ticket、opening 或 issuance ABI。
本版本 identifiers 指向**估算草案**；將來具體化的候選必須另取 profile ID。

## 固定欄位與 envelope

`TraceInputs(rid,sn,ctx,h)` 的 exact bytes 長度為 `32,16,32,32`。
`plaintext=rid||sn` 為 48 bytes，`associated_data=ctx||sn||h` 為 80 bytes。
`decode_trace_inputs` 拒絕長度錯誤及內外 serial 不一致。兩者為 canonical relation 的固定欄位，
沒有插入 prefix；它們的用途由 relation 與未來候選的 cryptographic domain 綁定。

Research ciphertext envelope 的精確 grammar：

```text
magic = ASCII("PQ-THRESHOLD-RESEARCH-CIPHERTEXT") || 0x00
version : uint16 little-endian = 1
candidate_length : uint8
candidate : exact ASCII bytes
profile_length : uint8
profile : exact ASCII bytes
payload_length : uint32 little-endian
payload : opaque bytes, 1..1,048,576
```

只有上述固定順序；不接受 unknown version、unknown／mismatched candidate/profile、別名、
NUL 結尾 identifier、錯誤 length、truncation、trailing bytes。Decoder 的 caller 必須從獨立
設定提供 `expected_candidate` 與 `expected_profile_id`，不能直接信任 envelope 自報的身份。
Python API 拒絕 bool 冒充 integer，固定欄位要求 exact `bytes`，不接受 mutable bytearray。

Envelope payload 故意保持 opaque：成功 decode 只證明共同 grammar 和 dispatch identity，
沒有驗證 polynomial packing、syndrome、KEM、NIZK 或 ciphertext 的數學有效性。
未定的 candidate payload grammar、hash domains、g、Δ、CAE、DKG、transcript 不在 v1 凍結範圍。
本 envelope 不含 plaintext、AD 或 authorization；更不會賦予 opening 權限。

## 草案 profiles 與拒絕行為

| Candidate | Profile ID | 估算依據 |
| --- | --- | --- |
| TH-GF | `gf-pompeii-d4-estimate-v1` | 底層 Pompeii Table 2，n=256,d=4,p=2^10；非完整 Fulham |
| TH-GF | `gf-pompeii-d9-estimate-v1` | 底層 Pompeii Table 2，n=256,d=9,p=2^11；非完整 Fulham |
| TH-UT | `ut-mlkem768-estimate-v1` | ML-KEM-768 1088-byte ciphertext 加未定 CAE expansion |
| TH-NIED | `nied-6688128-estimate-v1` | repository 208+48+32-byte 格式草案；最終分散式參數未定 |

Registry 為唯讀 closed-world mapping。共同 metadata 固定為 `implementation_stage=contract_only`、
`security_assessment=OPEN`、`threshold_execution=not_implemented`、
`opening_capability=interactive_required_adapter_open`、`production_qualified=false`。
`setup_model` 及 `open_parameters` 表達候選待具體化項目，未宣告已有可信 setup 或 DKG。

`get_backend(candidate,profile_id)` 預設 production，立即拋 `Unsupported`。
顯式 `purpose="research"` 僅取得 `UnavailableBackend`：
`encrypt_reference`、`check_encryption_relation`、`decrypt_reference_for_test`、`create_share`、
`start_opening`、`advance_opening`、`combine` 全部拋 `Unsupported`。
start/advance 的 object placeholder 並非 frozen session ABI；沒有序列化或成功路徑。
未知 purpose／profile 則為 `ContractError`。沒有 production 註冊或旗標切換捷徑。

## 大小與 evidence 類型

```text
B_ticket = 80 + B_C + B_sigma + B_extra
TH-NIED: B_C = 208 + 48 + 32 = 288
TH-UT:   B_C = 1088 + 48 + Delta_bytes
TH-GF:   B_C = 2*256*d*log2(p)/8 + 128 + 256*d/8 + g_bytes
```

`SizeEstimate` 以 component 名稱與 `int|None` 保存條件式估計。
`known_bytes` 只加總已知部分，**不是完整大小**；任一項未知，`total_bytes` 就是 `null`。
非負整數及總和都受 uint64 上限檢查；拒絕 bool、負值、float、NaN、重複 component 及 overflow。
`g_bytes` 只適用 GF，`delta_bytes` 只適用 UT，誤用即拒絕。

預設 `B_sigma=11644` 永遠標記 `provisional_estimate`；`B_extra`、g、Δ 預設未知。
caller 明確填 0 代表其情境假設，不能解讀為我們測得零 overhead 或零長度安全 tag。
`research_envelope_overhead_bytes` 只反映共同 grammar；未自動加入 B_C 或 B_extra。
若把此 envelope 放入 ticket，caller 必須把它連同其他 framing 一起計入 B_extra，避免遺漏
或重複計算。本版工具不是生產票證 serializer，因此沒有宣告最終 wire 大小。

`comparison_report` 的 `estimated` 僅能由 calculator 產生；`observed` 的 ciphertext、ticket、
opening rounds/time、satellite online bytes 全為 null。沒有接受或提升 observed 資料的 API。
`literature_reported` 保留獨立空陣列：現有論文實驗與本案 profiles 不同，數字保留在 fit 文件，
不搬進候選實測。這是 report generator 的資料流限制，並不是任意外部 JSON 的驗證器。

執行方式：

```bash
PYTHONPATH=src python -m pq_threshold_candidates
PYTHONPATH=src python -m pq_threshold_candidates --extra-bytes 0 --delta-bytes 28 --g-bytes 32
```

第二個命令只重現格式假設：GF d4/d9 ticket 14,572/18,508、UT 12,888、NIED 12,012 bytes；
全部是 estimated，sigma provisional。不代表選定 CAE、g 或安全層級。
CLI 只輸出 JSON，不產生 key、ciphertext、proof、assignment 或下載任何附件。
