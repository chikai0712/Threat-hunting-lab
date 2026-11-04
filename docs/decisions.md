# 架構決策記錄

日期：2026-11-04。狀態用「已確認原則／設計草案／待確認」區分，不以PoC中使用的技術代替部署決策。

## 已確認原則

| ID | 決策 | 理由與影響 |
| --- | --- | --- |
| ADR-001 | 本階段架構與文件先行 | 使用者要求先完成框架；環境確認後才繼續串接／部署實作 |
| ADR-002 | 支援多類網路、資安軟硬體Log | 來源需涵蓋Fortinet、Palo Alto、Cisco、Windows／AD、Linux、AWS、K8s |
| ADR-003 | 來源可透過環境變數設定IP | 降低接入設定成本；設備仍需配置PUSH目的地 |
| ADR-004 | 各來源有獨立正規化API | 保持來源契約可辨識，同時映射共同事件模型 |

## 採用中的設計草案

| ID | 草案 | 需驗證的影響 |
| --- | --- | --- |
| ADR-005 | Raw與Normalized皆可追溯 | 儲存成本、證據要求與retention待確認 |
| ADR-006 | 以持久化緩衝搭配冪等重送 | HTTP成功界線、broker及失敗隔離仍需選型 |
| ADR-007 | profile與實際device身份分開 | 後續加入device_id／site_id；PoC尚未完整實作 |
| ADR-008 | 回應提案、核准與執行分離 | 正式核准身份、policy與回復機制待環境定案 |
| ADR-009 | IP無法辨識多品牌共用出口時不猜測 | 決定HTTP分流、獨立listener或可信relay |

## 待確認決策

| ID | 問題 | 候選方向 | 決策所需證據 |
| --- | --- | --- | --- |
| OPEN-01 | 部署在哪裡 | 本機／VM／既有K8s／雲端 | 平台現況、owner、可用性 |
| OPEN-02 | 事件broker | 既有Kafka或其他平台／先單機緩衝 | EPS、斷線容忍、維運能力 |
| OPEN-03 | 搜尋與SIEM | 既有ELK／其他SIEM／新建 | 查詢、授權、成本與容量 |
| OPEN-04 | 共同schema | 內部schema／ECS映射／OCSF映射 | 下游工具、資料樣本 |
| OPEN-05 | 來源身份與TLS | IP搭配token／mTLS／可信agent | 設備能力、網路與代理 |
| OPEN-06 | 設備與站點識別 | 資產系統ID／registry | NAT／relay、資產盤點 |
| OPEN-07 | 保存與資料分級 | raw／index／case不同policy | 規範、敏感資料、成本 |
| OPEN-08 | 案件與調查平台 | DFIR-IRIS／既有系統、Velociraptor、Timesketch | 現有工具、權限與工作流 |
| OPEN-09 | AI／MCP | provider、模型、唯讀工具與資料外送policy | 可用服務、成本、資料邊界 |
| OPEN-10 | 部署規模與高可用 | 單節點／多節點／多站點 | SLO、RPO／RTO與預算 |

## 後續決策記錄格式

每次定案記錄：日期、決策ID、owner、問題、採用方案、考慮過的替代方案、取捨、環境證據reference、受影響文件／介面、驗收及回復方式。變更既有決策時以新紀錄取代並連結舊紀錄，不悄悄覆寫理由。

## AI模型整合增補（2026-11-04）

| ID | 狀態 | 內容／需驗證的影響 |
| --- | --- | --- |
| ADR-010 | 已確認原則 | 將使用者提供的Hugging Face資安模型研究納入架構文件，維持環境確認後再實作 |
| ADR-011 | 設計草案 | 偵測、生成分析與檢索分層；各能力以task adapter隔離 |
| ADR-012 | 設計草案 | LLM輸入為授權證據集合；輸出為含引用、未知項與分析師review的建議 |
| OPEN-11 | 待確認 | 精確模型repo／variant／revision、授權、runtime與量化相容性 |
| OPEN-12 | 待確認 | RAG資料來源、ACL、向量／混合索引與刪除／版本策略 |
| OPEN-13 | 待確認 | 任務評估資料、baseline、人工評分及效能門檻 |

這些項目補充OPEN-09的AI／MCP選型，不表示已選定某個模型。見 [AI分析架構](ai-analysis-architecture.md)。
