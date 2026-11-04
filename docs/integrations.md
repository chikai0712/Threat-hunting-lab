# 工具與平台整合矩陣

狀態：候選整合設計。選定產品、版本、授權與部署方式在環境確認後決定。本表不表示已連線或必須安裝所有工具。

| 能力 | 候選工具／平台 | 邏輯介面 | 已有PoC／目前差距 |
| --- | --- | --- | --- |
| 原始Log接入 | Syslog、HTTP、Fluent Bit、rsyslog | Raw envelope、來源profile | 有receiver及範例；未做實機驗證 |
| Endpoint訊號 | Wazuh | 告警JSON／collector | 四種原生adapter之一；僅最小樣本 |
| Network訊號 | Suricata、Zeek | EVE／conn／dns／http logs | Suricata告警樣本；Zeek欄位與關聯待實作 |
| Container訊號 | Falco、K8s agent | JSON／HTTP | Falco樣本與通用K8s映射；實機待驗證 |
| AWS訊號 | CloudTrail、CloudWatch Logs | HTTP relay／SDK／S3-SQS | 有CloudTrail樣本與CloudWatch poller；無帳戶接線 |
| 緩衝與串流 | Kafka／既有broker | Raw／Normalized／Alert／失敗紀錄 | 僅本機SQLite outbox；正式topic與consumer待定 |
| 搜尋與SIEM | ELK／既有SIEM | index mapping、查詢、retention | 無外部搜尋平台；PoC使用SQLite |
| 偵測規則 | Sigma、Python／ksqlDB | 版本化規則與Event references | 四條Python示範；Sigma範本未執行 |
| 主機調查 | Velociraptor | collection request／evidence reference | 設計，未呼叫API |
| 時間線 | Timesketch、Hayabusa | timeline事件／匯出 | 設計，未匯入外部平台 |
| Network分析 | RITA／自訂hunt | Zeek特徵、finding | 設計，未做beacon統計 |
| 案件管理 | DFIR-IRIS／既有平台 | case與alert/evidence對照 | 本地示範案件；外部同步待定 |
| 情資 | MISP、OpenCTI | 唯讀IOC／TTP enrichment | 設計，未連線 |
| 回應工作流 | Shuffle／既有SOAR | 經授權proposal／execution audit | PoC只有提案／自述核准，無執行器 |
| 攻擊模擬 | CALDERA、Atomic、Stratus | 授權test run／預期與觀察結果 | 僅設計，沒有執行攻擊 |
| 風險檢測 | Prowler、Trivy | posture／vulnerability findings | 後續候選，需與事件模型區分 |
| AI／MCP | 待選provider與工具server | 角色、唯讀查詢、證據reference | 僅[角色契約](../config/agents.yaml)，無模型接線 |

## 模組整合原則

每個adapter須說明來源版本、輸入格式、身分／權限、timeout／重試、idempotency、輸出schema與稽核。先定義邏輯介面，再依已選產品映射具體API；此階段不填假定的真實URL或secret。

已有SIEM、broker、案件或agent時，優先評估重用現況。第三方工具的支援版本、授權條款、資源成本與相依服務需在選型時逐項確認。

## 優先驗證情境候選

1. Endpoint：異常登入 → 告警 → 案件 → 主機證據reference。
2. Network：設備／Suricata訊號 → Zeek關聯 → 調查finding。
3. AWS：CloudTrail事件 → 正規化 → 規則命中 → 調查案件。

實際先做哪一項由可取得的設備／樣本與環境決定。驗收步驟見 [Roadmap](roadmap.md)，現有合成案例見 [PoC情境](poc.md)。

## AI能力整合候選

| 能力 | 研究候選 | 接入位置 | 狀態 |
| --- | --- | --- | --- |
| SOC／IR生成分析 | Foundation-Sec系列、MiST、CyberPal、Qwen3 baseline | Evidence bundle → task router → structured draft | 未查核精確repo；未部署 |
| 分類／TTP抽取 | SecBERT、CIRCL ATT&CK Classifier、TTPXHunter、ModernBERT phishing候選 | CTI／分類adapter → finding | 任務頭／標籤與郵件來源需求待確認 |
| Log異常 | LAnoBERT／來源統計baseline | 正規化事件序列 → anomaly finding | 來源適配與誤報驗證待完成 |
| RAG retrieval | BGE-M3與待選索引 | 有權限知識片段 → evidence bundle | ACL、語言與檢索品質待確認 |

名稱來自使用者提供研究筆記，非已確認產品規格；詳細查核欄位見 [模型候選矩陣](ai-model-candidates.md)。AI服務錯誤應降級到現有規則與人工調查，不阻斷Log接收。
