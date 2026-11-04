# 整合狀態與契約

本版沒有連線至任何外部資安平台。下列「範例轉接器」只表示能接收 `samples/` 中的最小 JSON 結構；正式工具版本與更多事件格式需另外驗證。

| 工具 | v0.1 狀態 | 下一個介面 |
| --- | --- | --- |
| Wazuh | 範例轉接器 | alerts.json → collector → /ingest |
| Suricata | 範例轉接器；只接受帶 alert 的事件 | eve.json → collector；flow/dns 等另建模型 |
| Falco | 範例轉接器 | JSON output / Falcosidekick webhook adapter |
| AWS CloudTrail | 範例轉接器；單筆事件 | S3/SQS consumer，拆開 Records 陣列 |
| Kafka / ELK / ksqlDB | 設計 | topic、mapping、consumer 與 DLQ |
| Sigma | 一份範本；不參與執行 | pySigma pipeline 與後端轉譯測試 |
| Velociraptor | 設計 | 經授權的 artifact collection，回傳證據 reference |
| Zeek / RITA | 設計 | conn/dns/http logs、統計特徵與 hunt query |
| Timesketch | 設計 | timeline CSV/JSON 匯出與查詢 |
| DFIR-IRIS | 設計；現在使用本地 SQLite 案件 | 本地 case ID ↔ IRIS ID、冪等同步 |
| Shuffle | 設計 | 具核准 token、稽核及回復步驟的 workflow |
| MISP / OpenCTI | 設計 | 唯讀 IOC enrichment 與可信度欄位 |
| CALDERA / Atomic / Stratus | 設計；不執行模擬 | test run ID、授權範圍與預期偵測結果 |
| Prowler / Trivy | 第二階段 | 雲端／映像弱點資料另外建 findings 模型 |

## Adapter 約定

輸入：`{"source":"cloudtrail","payload":{...}}`，以 `samples/` 為可執行契約。缺少必要欄位回傳 422。巢狀 payload 只做最小驗證，正式 collector 必須建立完整 vendor schema 與大小限制。

輸出：正規化 Event（見 `/docs`）。採接收端去重，生產環境需增加 queue、速率限制、TLS／mTLS、OIDC/RBAC、來源認證及保留策略。不能直接將本機 Lab API 暴露到網際網路。

## 三個第一階段整合里程碑

1. Wazuh 真實 alert 匯入後，以 case ID 記錄 Velociraptor 蒐證 reference。
2. Suricata 告警以五元組與時間窗關聯 Zeek 記錄，送 ELK 查詢；目前沒有 beaconing 統計偵測。
3. CloudTrail 由隔離 AWS 帳戶匯入；將 Stratus 測試 run ID 與命中告警關聯，計算實測結果。

大型第三方工具請依各自官方部署方式與相容版本獨立建置；本 repo 不把所有平台包成一個未驗證的 Compose stack。
