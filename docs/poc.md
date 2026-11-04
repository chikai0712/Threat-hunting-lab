# PoC 操作手冊

> PoC 參考文件：保留既有實作與操作資訊；當前階段為架構文件整理，環境確認後再安排實際串接／部署。請先閱讀 [文件索引](README.md)。

先依 README 啟動 API 並設定相同的 `DART_API_TOKEN`，執行 `python scripts/demo.py`。以下結果在全新資料庫成立。

| PoC | 範例 | 預期結果 | 尚未驗證的部分 |
| --- | --- | --- | --- |
| 1 Endpoint investigation | endpoint.json | authentication failure → T1110 告警 → 案件 | 真實 Wazuh 訊號、Velociraptor 蒐證 |
| 2 Network threat hunting | network.json | 高優先級 IDS 告警 → 案件 | 真實 Suricata／Zeek 關聯、C2／beaconing 判定 |
| 3 AWS incident detection | aws.json | 成功 StopLogging → T1562.008 告警 → 案件 | AWS collector、Stratus 模擬 |
| 4 Container runtime | container.json | container shell → T1059.004 告警 → 案件 | Falco live feed |

## 案件與核准展示

1. 在 `/docs` Authorize 後呼叫 `GET /cases`，複製一筆 case id。
2. 呼叫 `GET /cases/{case_id}` 查看初始時間線。
3. 以 `collect_evidence`、虛構主機名稱與 rationale 呼叫 `POST /cases/{case_id}/responses`。
4. 複製 proposal id，呼叫 `POST /responses/{proposal_id}/approve`，填入 reviewer 與 note。
5. 預期 status 為 approved、execution_enabled 為 false；再次核准回傳 409。
6. 重播 demo，事件與案件總數保持 4。

## 驗收界線

這些 PoC 驗證的是軟體資料流，不代表偵測率、精確率、MTTD、MTTR 或真實工具相容性已達標。真實 Purple Team 測試需記錄 run_id、授權帳戶／主機、預期 technique、起訖時間、觀察到的告警、未命中原因及清理結果；本版尚未有此 measurement engine。

## 排錯

- 啟動時 token 錯誤：產生至少 24 字元隨機 token。
- 401：確認呼叫端與服務端使用相同 `X-API-Key`。
- 422：比對 samples 格式；timestamp 必須附 `Z` 或時區 offset。
- Docker 無法連線：啟動 Docker Desktop，或使用 Python 快速開始。
- 想重新展示：停止 API 後改用新的 `DART_DB_PATH`，保留既有案件資料。
