# 授權與來源

原 PQC_auth source snapshot 沒有 repository 根 LICENSE。本次保留既有檔頭與來源，
不自行替作者程式指定新的授權；公開可讀不自動授予其他授權。

Rust research fork 基於 Binius64 commit
`4428e759dd27956bd5b9ae5025d67eb8ccc1accf`。
上游 dual MIT／Apache-2.0 原文保存在 dependencies/binius/；既有 adapter／patch 與來源 pins 保留。
Cargo registry dependencies 的精確版本與下載 archive checksums 在 Cargo.lock，
各 package 的授權仍以原 package 為準，沒有 vendoring crate binaries/source。

Native C 使用系統 OpenSSL libcrypto、GCC OpenMP／libgomp 與系統 libc；
這些系統程式庫未複製入 repository。compiler／rlibs 亦為外部輸入，不是本分支的 binary 發布。
本 snapshot 沒有包含原倉庫的 ML-DSA vendored native source，因此其獨立 NOTICE 不需被錯置成全庫授權。
