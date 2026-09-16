# TH-GF 單機 reference profile v1

本文件凍結本輪**局部研究 reference** 的選擇，以便重現 codec、演算法與測試。
它不凍結 production profile，也不把所有具體 hash／DEM 選擇標為 paper-verified。
完整機器描述見 [reference_profile_v1.json](reference_profile_v1.json)。

## 選擇 TH-GF 的理由

TB1 已列出三候選的缺口。本環境沒有 ML-KEM 專用 backend 或真實 Goppa key／decoder；
TH-UT 尚須選定 CAE，而 TH-NIED 的現有 matrix 是 test fixture。
TH-GF Fig. 14 的整數／環演算法可直接由原文建立獨立係數對照，適合作第一個實際尺寸的
單機 reference。這是工程先後順序，沒有依未實測的 threshold runtime 或安全強度選出最終贏家。

## 原始來源及 revision

本輪重新核對附件 `2021-096.pdf`：695,683 bytes，SHA-256
`b730d4640218b5ea86b019a52501be2e4682b562e61a468abd08658ee393678e`。
題名為 *Gladius: LWR based efficient hybrid public key encryption with distributed decryption*。
既有來源索引的 catalog attribution 為 2021-08-31、五次 revision 的最後一次，PDF metadata
日期亦一致；publisher-hosted bytes 尚未比對，不能進一步宣稱 exact upstream revision identity。
詳見 [原始來源索引](../SOURCE_INDEX_zh-TW.md)。

本輪直接重讀 exact attachment 的 pp. 8–10、23–24、44–46，並渲染檢視 p. 45 Figure 14。
出版來源可由 [ePrint 2021/096](https://eprint.iacr.org/2021/096) 取得。
沒有下載第三方實作、安裝 crypto 套件或把原始 PDF／抽出文字／渲染圖片加入 Git。

| 本輪項目 | 原文位置 | Evidence 類型 |
| --- | --- | --- |
| centered representative `(-q/2,q/2]`，所有 modulus 同規則 | p. 8 Notation | paper-verified |
| CBD1：兩獨立 bits 的差，variance=1/2 | p. 8 D_sigma 的 NewHope sampling，取 B=0 | paper-verified sampling 形式；seed/XOF framing 為 project choice |
| nearest rational rounding、ties toward zero | p. 9 LWR map | paper-verified；實作為 exact integers |
| `R_q=Z_q[X]/(X^n+1)` 與 Module-LWR | pp. 9–10 | paper-verified |
| `A2=A1*R1+R2+ell*I`，deterministic Enc、Dec、reencryption | Fig. 14 p. 45 | paper-verified，逐係數獨立測試 |
| n=256,d=4,t=2,q=4188161,p=1024,ell=1048576,mu_scale=256 | Table 2 p. 46 第二組 prime-q 的 d4 列 | paper-verified 底層參數；非完整安全資格 |
| Hybrid2 的 c1,c2,c3,c4 及 H/H'/H''/G 順序 | Fig. 5 p. 24；domains 在 §3.2 p. 23 | paper-verified construction 結構 |
| SHAKE256 具體 domains、g=32、128-byte OTP、80-byte AD 前置 | 本文件及 source | 本案 reference 選擇；不是原文固定實例 |

底層 Table 2 的 security 欄位彼此不同，不能由選用這一列推得某個標準安全等級，
更不能宣稱等同 ML-KEM-768。省略 LVP 的參數分支也未消除 bad-key／failure 的研究義務。

## Pompeii 的精確實作

矩陣採 d×d、每格 n 個升冪係數。內部係數一律用 centered integers；n=256、d=4。
環乘法採 exact integer negacyclic convolution，`X^n=-1`，沒有浮點 FFT 或近似 rounding。
q 為奇數時 canonical 區間為 `[-(q-1)/2,(q-1)/2]`；p=1024 時為 `[-511,512]`。
尤其 `-p/2` 必須映到 `+p/2`。

原文 KeyGen 的目標分佈：A1 uniform in `R_q^(d×d)`；R1/R2 係數為 CBD1；
`A2=A1*R1+R2+ell*I`。Gadget 只在對角 polynomial 的常數項加 ell。
pk=(A1,A2)，sk=(pk,R1)。這是 full-key generation，沒有 secret sharing。

Deterministic Pompeii message u 是 `R_2^d`，即 1024 bits／128 bytes。
這裡的 t=2 是 message coefficient modulus，與 OA threshold 無關。

```text
c1a = Round_q_to_p(u^T * A1)
c1b = Round_q_to_p(u^T * A2)
w   = Center_q(c1b - c1a * R1)
e   = Center_p(w)
v   = Center_mu_scale(e)
u'  = (e-v)/mu_scale
```

rounding 先 center mod q，再以整數除法將 `p*x/q` 四捨五入，恰好一半時向零。
解密把 packed c1a/c1b **先還原為 centered mod-p 代表元，再帶入 mod-q 運算**；
直接把非負 wire residues 當成整數 lift 會改變方程。所有 decoded u' 係數必須在 `{0,1}`；
重新計算 `(c1a',c1b')` 並完整比較，失敗回傳 `None`。不接受只靠 rounding 還原的候選明文。

## Hybrid2 與 48/80-byte trace

本 profile 的 c1 是兩個 Pompeii ciphertext vectors 的拼接；不是再次加一份 c1。
採 Fig. 5 的 deterministic base PKE 路徑，變數重新命名以區分 secret u、DEM key 與 mu_scale：

```text
u  <- {0,1}^1024
c1 = Pompeii.Enc(pk,u)
pad = H(u)                           # 128 bytes, the one-use DEM key
mu_hash = H_prime(u)                 # 128 bytes, an element of R_2^d
c2 = (ad || rid || sn) XOR pad       # 128 bytes
c3 = G(c2,mu_hash)                   # 32 bytes, g=32 in this local profile
c4 = H_double_prime(u)              # 128 bytes, an element of R_2^d
```

所有 hash 為 SHAKE256，四個 label 分別為 ASCII `H`、`H_prime`、`H_double_prime`、`G`。
每個 hash input 都是下列精確 framing：

```text
ASCII("PQ-TH-GF-TB2") || 0x00 || uint16le(1)
|| uint8(len(profile_id)) || ASCII(profile_id)
|| uint8(len(label)) || label
|| (uint32le(len(arg_1)) || arg_1) || ...
```

H/H'/H'' 的唯一 arg 是 128-byte u；G 的兩個 args 依序為 c2、mu_hash。
Profile ID 是 `gf-hybrid2-pompeii-d4-shake256-otp-ref-v1`。
OTP 不需要額外 DEM randomness／nonce；新 ciphertext 需重新抽樣 secret u。
外部 witness harness 若重用 u，會重用 pad，因此它只能作可重現研究介面，不能作正式隨機性管理。

解密先執行 Pompeii 的重新加密檢查，再驗證 c4、再驗證 c3，最後才 XOR 還原。
解出的前 80 bytes 必須與 caller AD 相同，內部 serial 也必須等於 AD 的 serial。
成功只回傳 48-byte plaintext；不回傳 u、pad 或 mu_hash。
本 reference 的 caller AD 尚未接上已驗證 TicketView，不構成授權開啟。

H/H'/H''/G 的 random-oracle proof model 不等於已證明這個具體 SHAKE256 profile。
本輪沒有採用論文 §6 的 MPC-friendly G 優化，不能搬用其 distributed 成本。

## KeyGen 隨機性與編碼

正常研究呼叫 `keygen_reference()` 由 `secrets.token_bytes(32)` 取得 seed；
`keygen_reference_for_test(seed)` 是明示可重現 harness，seed 可推得完整 sk。
用相同 framing 與 `KEYGEN-A1`、`KEYGEN-R1`、`KEYGEN-R2` 分離三個 SHAKE256 streams。
A1 每次讀 3 bytes，取低 22 bits；值小於 q 才接受。R1/R2 每個係數讀一 byte 的低兩 bits
並相減。這是局部確定化選擇；sampling 的 rejection 與 stream 延伸均有獨立測試。
實際 stream 共用一個 32-byte seed 並分離 domains，因此對原文獨立隨機抽樣的模擬依賴
SHAKE256 expansion 的計算假設，不能稱為 information-theoretically independent entropy。

Wire coefficients 採非負 residues，每個 polynomial 按升冪、matrix 按 row-major，
連續 little-endian bit packing。PK 用 22 bits 並拒絕 `value>=q`；Pompeii ciphertext
用 10 bits；u 用 1 bit。Decoder 拒絕非零 unused tail bits；本 profile 的完整物件均對齊 bytes。
PublicKey 形狀驗證不證明 key 由正確 KeyGen 產生，也不建立 public key 的安全資格。

本 candidate 的 record grammar 是獨立 namespace，沒有修改 TB1 envelope：

```text
magic = ASCII("PQ-TH-GF-TB2") || 0x00
version: uint16le = 1
kind: uint8 = 1 (public key), 2 (ciphertext), or 3 (secret witness)
profile_length: uint8
profile_id: exact ASCII
payload_length: uint32le
payload: exact kind-specific bytes
```

所有欄位順序、版本、profile、kind、length 必須精確匹配；拒絕 truncation、trailing bytes
及 alternate encoding。Full secret key 沒有序列化 API；secret key／witness 的 repr 隱藏內容。
Witness record 仍是秘密資料，不能因可編碼而進入 Git、benchmark output 或公開 audit。

| 物件 | Payload bytes | Record overhead | Record bytes |
| --- | --- | --- | --- |
| Public key（兩個 d×d matrices） | 22528 | 62 | 22590 |
| Ciphertext（2560+128+32+128） | 2848 | 62 | 2910 |
| Witness u（秘密） | 128 | 62 | 190 |

本輪 ciphertext/public-key 長度已有 reference 實測；witness 行是固定 grammar 算術。
Ticket 尚未整合：provisional sigma=11644 時，`80+2848+11644=14572` 只是已知部分。
若未來 C 採整個 candidate record，還需加入其 62 bytes 及其餘 framing；工具保留 extra=null。

## 驗證的實際限度

新測試以不同係數求和公式核對環乘法及完整 KeyGen 方程，用 Fraction 算術與獨立 bit packing
核對 Pompeii encryption，並用 literal domain framing 核對 Hybrid2 c2/c3/c4。
公開 digest vectors 由本地 fixture 生成，用來偵測回歸；**不是原論文或 upstream KAT**。
完整 decryption 的正式獨立實作／外部 KAT 尚缺，round-trip 與 rejection 測試不能取代 failure
bound、QPT reduction、side-channel review 或 independent cryptographic review。
