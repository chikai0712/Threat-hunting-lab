# 架構文件索引

文件基準：2026-11-04。本版用途為架構討論與後續實作規劃，部署環境尚未確認。

## 閱讀順序

1. [需求與範圍](requirements.md)：了解要解決的問題與階段界線。
2. [系統架構](architecture.md)：確認邏輯模組與資料流。
3. [來源接入設計](source-ingestion.md)：確認設備如何 PUSH 及來源如何識別。
4. [API 與資料契約](contracts.md)：確認資料格式與處理語義。
5. [環境確認表](environment-checklist.md)：收集實作所需資訊。
6. [架構決策記錄](decisions.md)、[工具整合矩陣](integrations.md)：確認選型與依賴。
7. [分階段計畫與驗收](roadmap.md)：以環境盤點結果決定後續工作。

## AI 資安模型整合文件

- [AI分析架構](ai-analysis-architecture.md)：Detection、Reasoning、Knowledge Retrieval三層與既有Log／案件流程。
- [模型候選矩陣](ai-model-candidates.md)：使用者提供的Hugging Face候選及待查核清單。
- [AI契約與評估](ai-contracts-evaluation.md)：分析API草案、證據引用與三種PoC的評估方法。

這三份均為設計文件，未部署模型、RAG或AI API；模型repo、版本、授權與效能未於本輪線上核實。

## 狀態定義

| 標示 | 意義 |
| --- | --- |
| 已確認原則 | 使用者已表達的需求或目前採用的文件規劃原則 |
| 設計草案 | 供檢視的目標介面／流程；可能因環境調整 |
| 待確認 | 必須取得實際環境資訊才能定案 |
| PoC 參考 | 已有程式或範例，可用於驗證設計；不代表完成正式接入 |

## PoC 參考文件

| 文件 | 用途 |
| --- | --- |
| [操作手冊](prototype-guide.md) | 原 README 的安裝、啟動、Demo 與 API 操作 |
| [實作架構](prototype-architecture.md) | 單程序／SQLite 實作記錄 |
| [環境變數與來源 PUSH](environment-push.md) | v0.3 已實作的環境變數與 endpoint |
| [通用 Log 收集](log-collection.md) | 獨立 collector、TLS、檔案、CloudWatch 與 agent 範例 |
| [PoC 情境](poc.md) | Endpoint／Network／AWS 等示範流程 |
| [安全與資料邊界](../SECURITY.md) | 現有程式的限制與資料處理界線 |

設計文件描述目標責任與契約；實際 PoC 行為以程式及相應操作手冊為準。若兩者不同，應記錄差距並安排實作，不將設計草案當成已完成的功能。
