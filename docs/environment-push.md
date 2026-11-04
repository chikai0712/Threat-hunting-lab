# 只填來源 IP：環境變數與獨立正規化 API

v0.3 可以用 `.env` 管理來源。填入設備／agent 的來源 IP 後，該來源的 PUSH API 與 Syslog 路由即啟用；不需修改 Python 或另啟動 collector process。

## 1. 建立環境設定

```bash
python3 scripts/init_env.py
```

此指令從 `.env.example` 建立 `.env`，自動產生管理 API token，不會覆蓋既有 `.env`。如果你已有舊版 `.env`，請把 `.env.example` 的新欄位補進去。

編輯 `.env`，填入實際設備／送出 Log 的 agent IP。下列皆為文件示範位址，請替換：

```dotenv
LISTEN_IP=0.0.0.0
HTTP_PORT=8000
SYSLOG_PORT=5514
SYSLOG_ENABLED=true

FORTINET_IPS=192.0.2.10
PALOALTO_IPS=192.0.2.11
CISCO_IPS=192.0.2.12,192.0.2.13
WINDOWS_IPS=192.0.2.20
LINUX_IPS=192.0.2.30
AWS_IPS=192.0.2.40
KUBERNETES_IPS=192.0.2.50
```

- `LISTEN_IP`：**這台收集伺服器**要監聽的位址；`0.0.0.0` 代表所有 IPv4 介面。設備端目的地須填伺服器真實 IP，不能填 `0.0.0.0`。
- `*_IPS`：**傳送端**的實際 IP，可填單一 IP、多個逗號分隔 IP 或 CIDR，例如 `192.0.2.0/28`。
- 留白即停用該來源，HTTP 回 403；Syslog 的未授權來源不入列。
- 設定在啟動時載入，修改 `.env` 後需重新啟動服務；既有 process 環境變數優先於 `.env`。

## 2. 啟動服務

### Python（優先建議用來驗證實際來源 IP）

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
threat-lab
```

`threat-lab` 自動讀目前目錄的 `.env`，啟動 HTTP API 與 TCP／UDP Syslog listener。請在 repo 根目錄執行。內建 listener 使用單一 process，不要增加 Uvicorn workers，否則會重複綁定同一 Syslog port。

### Docker Compose

```bash
docker compose up --build -d
# 修改環境設定後套用：
docker compose up -d --force-recreate
```

Compose 現在同時開放 HTTP 8000 與 Syslog 5514 TCP／UDP（可用環境變數調整），啟動內建接收器；不需要另外執行 `threat-log-collector`。

**Docker Desktop、NAT、反向代理可能改寫來源 IP。** 本版只信任 socket peer，不讀 X-Forwarded-For。若容器看到的是共用 gateway，便無法靠原始設備 IP 區分 Syslog；請使用主機原生 Python 部署或保留來源 IP 的 Linux 網路配置。不要將 gateway 的 IP 設成所有來源以假裝能辨識每台設備。

## 3. 設備 PUSH 目的地

假設收集伺服器 IP 為 `192.0.2.100`：

| 來源 | 環境變數 | 獨立正規化 API |
| --- | --- | --- |
| Fortinet | `FORTINET_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/fortinet` |
| Palo Alto | `PALOALTO_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/paloalto` |
| Cisco | `CISCO_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/cisco` |
| Windows／AD | `WINDOWS_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/windows` |
| Linux | `LINUX_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/linux` |
| AWS | `AWS_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/aws` |
| Kubernetes | `KUBERNETES_IPS` | `POST http://192.0.2.100:8000/api/v1/logs/kubernetes` |

**只有 Syslog 功能的設備**：設定 Remote Syslog destination=`192.0.2.100`、port=`5514`、protocol=`TCP` 或 `UDP`。內建接收器依 socket peer IP 選擇相同的來源 normalizer，直接寫入 Log／Event，並不要求設備會呼叫 HTTP。

**支援 HTTP 的設備／agent**：使用上表 URL，送 JSON object／array、NDJSON 或逐行純文字。AWS API 額外支援 CloudTrail `{"Records":[...]}`。AWS 這裡的 IP 是**轉送器／Lambda egress／agent 的 IP**，不是 AWS 所有服務的任意 IP；AWS 服務不會因你填了 IP 就自動將 Log 送來。CloudWatch 輪詢仍可用先前的 collector。

設備端仍需啟用 Log forwarding 並填入目的地；設定 `.env` 不會遠端修改防火牆、交換器或雲端平台。Windows／Kubernetes 可沿用 `config/collectors/` 的 Fluent Bit 範例，將 Host 改為收集器 IP，URI 改為上表端點。

## 4. HTTP 範例與結果

從 `FORTINET_IPS` 允許的機器執行：

```bash
curl -X POST http://192.0.2.100:8000/api/v1/logs/fortinet \
  -H 'Content-Type: text/plain' \
  --data 'devname="fw-01" type=traffic action=deny srcip=192.0.2.10 dstip=198.51.100.20 srcport=12345 dstport=443'
```

回傳包含 `accepted`、`log_id`、`parser_status`、`normalized`。正規化資料的共同欄位包含：

```json
{
  "schema_version": "1.0",
  "normalizer": "fortinet-v1",
  "source": "fortinet",
  "vendor": "Fortinet",
  "product": "FortiGate",
  "host": "fw-01",
  "category": "traffic",
  "action": "deny",
  "source_ip": "192.0.2.10",
  "destination_ip": "198.51.100.20",
  "source_port": 12345,
  "destination_port": 443
}
```

實際回傳另有 timestamp、timestamp_basis、severity、event_code、user、outcome 等欄位；無法辨識的值為 null 或保留通用 message。原始 raw、解析欄位與正規化結果共同保存，可用 `GET /logs?source=fortinet` 查詢。

## 正規化範圍

| Normalizer | 目前映射 |
| --- | --- |
| fortinet-v1 | key=value／CEF／JSON 中的 action、type、logid、src/dst IP/port；eventtime epoch 秒／毫秒／奈秒 |
| paloalto-v1 | 預設 TRAFFIC／THREAT CSV 的共同欄位；CEF／JSON 命名欄位。不支援全部 PAN-OS 類型／自訂順序 |
| cisco-v1 | `%FACILITY-SEVERITY-MNEMONIC` 事件代碼、動作與 severity |
| windows-v1 | Fluent Bit 常見欄位／Event.System 結構、EventID、Computer、EventData；4624／4625 登入結果 |
| linux-v1 | Syslog 及 SSH Failed password 中的使用者、來源 IP／port、登入失敗 |
| aws-v1 | CloudTrail eventName、eventTime、userIdentity、sourceIPAddress、errorCode |
| kubernetes-v1 | log message 與 kubernetes namespace／pod／container metadata |

這些為有測試的初版映射，尚未逐一實機驗證所有廠牌版本。Syslog 無年份／時區、Palo Alto CSV 本地時間等不會任意轉成 UTC；無可靠 event time 時使用接收時間並標記 `timestamp_basis=received`。舊版已儲存資料不會自動補做新正規化。

## IP 權限與網路行為

- `SOURCE_PUSH_REQUIRE_TOKEN=false`（預設）：來源 PUSH API 只需已設定的來源 IP；讀取、管理及舊版通用 API 仍必須提供 `X-API-Key`。
- 要求來源 HTTP 同時提供 token：設定 `SOURCE_PUSH_REQUIRE_TOKEN=true`。這不改變 Syslog 的 IP allowlist；Syslog 無 HTTP header。
- 所有 HTTP IP 判斷取實際 socket peer。`threat-lab` 已關閉 Uvicorn proxy headers；若自行用 Uvicorn 啟動，必須加 `--no-proxy-headers`。
- Syslog 依 IP 自動辨識，跨來源不可設定重疊 CIDR／同一 IP，系統會拒絕啟動並指出衝突。同一品牌多台設備可以共用一個來源 profile。
- 共用 NAT／集中轉送器 IP 無法自動判別不同廠牌的 Syslog；改走不同 HTTP endpoint，並設 `SYSLOG_ENABLED=false`，即可允許各 HTTP profile 使用相同 sender IP。
- IP 是路由與存取範圍，不是密碼學身分驗證；UDP 來源可偽造。僅在可控網段使用 IP-only PUSH。跨網段加密可用現有獨立 TLS collector 或具適當驗證的網路層。
- 內建自動路由 listener 目前為 TCP／UDP 明文。獨立 `threat-log-collector` 的 TLS 功能仍可用，但不由這份 `.env` 自動配置。
- 原始 Log／正規化 Event 會先由 outbox 持久化後入主資料庫；HTTP PUSH 直接以 transaction 保存。UDP 不保證交付。

用管理 token 呼叫 `GET /api/v1/sources` 可以查看啟用來源、允許 IP、endpoint 與 normalizer 版本；不會顯示 token。
