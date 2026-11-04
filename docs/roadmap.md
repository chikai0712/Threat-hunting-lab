# Roadmap

## Phase 0 — 本次初版

- [x] 正規化事件模型與四種最小轉接器
- [x] 四條示範規則與本地案件資料流
- [x] 回應提案／核准紀錄，禁止自動執行
- [x] 合成資料、API 文件、測試與 CI

## v0.2 — 通用 Log 收集

- [x] Syslog UDP／TCP／TLS、HTTP JSON／NDJSON、檔案續讀與 CloudWatch poller
- [x] Raw 保存、通用解析、outbox 重試、cursor 查詢與去重
- [x] 七類來源的接法與 Fluent Bit／rsyslog 範例
- [ ] 各廠牌／韌體實機驗證、Palo Alto CSV 與更多設備專用 parser
- [ ] 佇列容量／retention、收集器監控與完整失敗資料處理

## Phase 1 — 真實資料與調查

- [ ] 優先完成 Wazuh + Velociraptor、Suricata + Zeek、CloudTrail 三條路徑
- [ ] Collector 重試、Kafka topics／DLQ 與 Elasticsearch mappings
- [ ] Timesketch 證據時間線與 DFIR-IRIS 冪等案件同步
- [ ] OIDC、RBAC、獨立核准者、完整 audit trail 與資料生命週期

## Phase 2 — 偵測品質

- [ ] Sigma 執行／轉換測試與版本化規則管理
- [ ] 時間窗關聯、告警聚合及誤報標記
- [ ] 授權 Lab 的 CALDERA／Atomic／Stratus 測試 run tracking
- [ ] 以實測 run 計算 ATT&CK coverage gaps 與 MTTD

## Phase 3 — Agent 輔助與部署

- [ ] 五種 Agent 的唯讀 MCP adapter、工具 allowlist 與引用證據
- [ ] 經驗證的人工作業核准流程、Shuffle 受控執行與回復
- [ ] Kubernetes／AWS IaC、Secrets 管理、網路隔離與容量測試

每個階段應以可重現的整合測試及合成／已去識別化資料驗收，避免將示範規則誤認為正式偵測能力。
