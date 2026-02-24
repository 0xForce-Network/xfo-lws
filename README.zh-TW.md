# xfo-lws

0xForce 輕量錢包伺服器 — 實作 [Monero 輕量錢包 REST API](https://github.com/monero-project/meta/blob/master/api/lightwallet_rest.md)（MyMonero 相容）。

客戶端可透過 REST API 提交 Monero 檢視金鑰，伺服器會在背景持續掃描區塊鏈上的入帳交易。

與 OpenMonero 的差異：
- 使用 LMDB 取代 MySQL
- 檢視金鑰儲存於資料庫 — 持續背景掃描
- 使用 ZeroMQ 介面連接 `monerod`，支援鏈訂閱（push）
- 使用 Monero 專案的 amd64 ASM 加速（如可用）
- 支援 webhook 通知，包含「0-conf」通知

## 快速開始（Docker）

```bash
docker pull ghcr.io/vtnerd/xfo-lws
```

## 從原始碼建置

```bash
git clone https://github.com/vtnerd/xfo-lws.git
mkdir xfo-lws/build && cd xfo-lws/build
git submodule update --init --recursive
cmake -DCMAKE_BUILD_TYPE=Release ../
make -j$(nproc)
```

建置結果位於 `xfo-lws/build/src`。

## 執行

```bash
./src/xfo-lws-daemon
```

使用 `./src/xfo-lws-daemon --help` 列出所有可用選項。

## 授權

詳見 [LICENSE](LICENSE)。

---

完整的進階建置說明、Docker 標籤與版本資訊，請參閱英文版 [README.md](README.md)。
