# Evaluation 與 evidence

## 量測分區

1. Offline issuance：proof／ticket size、proving time、memory、storage。
2. Satellite online path：M1–M3 bytes、UE sign／KEM time、FGS verify／encap time、RTT。
3. Lifecycle：store latency、contention、restart／recovery、backhaul critical path。
4. Opening：authorization、share generation、combine time與audit size。

## 目前位置

- 正式實驗紀錄：`experiments.md`
- Access benchmarks：`benchmarks/access_nizk/`、`benchmarks/access_holder_auth/`
- Machine evidence：`manifests/`、`artifacts/metadata/`

D4 ML-DSA 與 D4b FAEST 的 wire／timing 是 prototype observation；12,126-byte ticket 仍含
provisional issuer-signature fixture，因此不能宣稱 production handshake 已低於 50,000 bytes。

