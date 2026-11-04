# AI 分析契約與評估計畫

狀態：設計草案；以下路徑、資料物件與狀態尚未實作，不屬於目前FastAPI可呼叫功能。

## 邏輯 API 草案

| 方法／路徑 | 用途 | 身分與限制 |
| --- | --- | --- |
| POST /api/v1/analysis/jobs | 建立triage／hunt／investigation／RCA草稿任務 | 已驗證分析師或授權服務；不是設備IP-only PUSH權限 |
| GET /api/v1/analysis/jobs/{job_id} | 查詢進度、結果與引用 | 檢查case／evidence讀取權限 |
| POST /api/v1/analysis/jobs/{job_id}/reviews | 記錄採用／修改／拒絕與理由 | 可驗證reviewer；不觸發遏止措施 |

建立成功預計回202與job_id，表示任務已持久化排隊。狀態：queued → running → completed／insufficient_evidence／needs_review／failed；取消／期限與配額回應待實作時定義。HTTP契約與分析成功分開，模型回覆不等於已驗證的安全結論。

任務輸入只指定授權的case ID、事件references、task type、時間範圍與問題。後端依呼叫者權限讀取證據、建立immutable bundle，避免使用者直接指定任意外部工具或模型endpoint。

```json
{
  "task_type": "incident_triage",
  "case_id": "case-demo-001",
  "event_refs": ["event-demo-001", "event-demo-002"],
  "question": "整理已知異常與下一步需確認的證據",
  "requested_model_profile": "security-triage-candidate"
}
```

requested_model_profile只能選registry中已核准且適用該資料範圍的profile；本範例字串不對應已部署模型。Idempotency-Key需綁定caller、任務型別、case及輸入hash，禁止用同一key重寫不同任務。

## Evidence bundle 契約

| 欄位 | 語義 |
| --- | --- |
| bundle_id／created_at | 不可變輸入快照與建置時間 |
| case_id／event_refs／raw_refs | 可授權回查的證據；raw可能僅reference而不送模型 |
| event_time_range／query_refs | 調查時間窗與資料取得方式 |
| normalized_events／correlations | 限定大小的事件與已有關聯，不填未確認因果 |
| retrieval_refs | doc_id、revision、chunk_id、有效日期與權限範圍 |
| redactions／truncation／missing_evidence | 遮罩與裁切紀錄、缺少哪些必要資料 |
| schema／normalizer versions | 讓輸入可重現與追溯 |

取資料時與顯示結果時都應重新檢查caller權限。快取key必須考慮資料範圍、文件版本與policy版本；不能把另一使用者或案件的檢索結果直接重用。

## 分析輸出契約

| 欄位 | 要求 |
| --- | --- |
| job_id／case_id／bundle_id | 關聯分析工作、案件及輸入快照 |
| summary | 摘要，區分觀察事實與推論 |
| hypotheses | 每項含說明、支持／反對證據、未知項與下一步驗證 |
| suspected_techniques | technique ID、ATT&CK版本、理由與證據references；允許空陣列 |
| evidence_references／knowledge_references | 區分事件事實與背景知識；不可捏造來源 |
| suggested_severity | 暫定分級及理由，不覆寫正式事件級別 |
| uncertainty | 資訊不足、矛盾、資料缺口；可選的模型自述信心不能當成機率 |
| recommended_investigation | 步驟、所需證據、預期能排除／支持什麼 |
| recommended_containment | 建議、影響、前提與回復方式；一律require_approval=true |
| provenance | model repo/revision、prompt／retrieval版本、runtime與量化設定、輸入hash |
| reviewer_status | pending／accepted／edited／rejected，與執行核准分開 |

輸出驗證至少檢查結構、reference存在／權限、technique ID版本及工具allowlist；證據支持度另由規則與分析師評估。只保存可審核的理由與證據摘要，不要求收集模型內部推理過程。

## 三個候選驗證情境

| 情境 | 輸入 | AI輸出 | 人工驗證點 |
| --- | --- | --- | --- |
| Incident Triage | 已正規化且關聯的告警、runbook、歷史案件 | 摘要、可能原因、證據缺口與下一步 | 事實有引用；分級與建議合乎環境 |
| Log Anomaly Detection | 指定來源正常／異常序列及時間切分資料 | anomaly score與finding | 誤報、漏報、來源漂移；不能直接等同攻擊 |
| AI Threat Hunting | CTI、ATT&CK版本、Zeek／endpoint可用欄位 | hunt hypothesis、查詢草稿與驗證計畫 | 查詢schema正確、唯讀、有限時窗／範圍，無資料亦可合理棄答 |

## AWS 調查 walkthrough（設計案例）

CloudTrail事件由aws來源API正規化 → 規則識別可疑AssumeRole或IAM修改 → correlation依主體、session與時間建立證據bundle → RAG提供適用AWS playbook → 模型提出假設／ATT&CK候選／待確認項 → 分析師查驗 → 保存案件草稿 → 回應建議交由獨立核准流程。

大量S3讀取需適用的data events；外傳判定可能還需要網路／proxy／flow資料，不能只因AssumeRole就推論資料遭竊。帳戶、資產重要性與合法變更紀錄也是必要上下文；缺漏時應標示insufficient_evidence。

## 評估方法

依事件時間、設備／站點與案件分組切分資料，避免同一incident或近重複樣本同時進train／test。測試文件避免進入RAG知識庫造成洩漏；固定模型、prompt、檢索與量化版本，記錄無RAG與有RAG、規則baseline與通用模型baseline。

| 任務 | 指標 | 驗收門檻 |
| --- | --- | --- |
| 分類／異常 | precision、recall、PR-AUC、每來源每小時false positives、detection delay | 依標籤品質與SOC負載訂定，待確認 |
| RAG | recall@k、引用準確性、過期內容率、ACL隔離測試 | 待知識庫與使用情境定案 |
| Triage／RCA | 事實支持率、無依據claim、引用正確性、棄答品質、分析師修改／採用率 | 需固定rubric與分析師標註，待確認 |
| ATT&CK／Hunt | multi-label precision/recall、證據支持度、查詢可執行與範圍正確性 | 不以只提到technique名稱計成功 |
| 服務 | p50/p95延遲、吞吐、queue wait、timeout、VRAM/RAM與成本 | 依硬體與案件量決定 |
| 權限／韌性 | 注入文字、跨案件資料、模型離線、無資料、矛盾證據、無效schema | 必須遵守既定資料／工具政策並可降級 |

LAnoBERT之類研究checkpoint需特別驗證來源差異、模板變化與正常資料適配；研究資料集分數不直接作為企業Log效能。模型升級、量化、prompt、embedding或分段變更都需回歸評估，保存結果與選型理由。

## 實作前環境資訊

GPU型號／數量／VRAM、CPU/RAM、可用disk、runtime支援、模型下載權限、網路出口、資料外送範圍、語言、案件量、context大小、知識庫ACL、推論延遲／成本目標與模型license。這些欄位未確定前，不承諾本機能同時執行哪些模型或回應速度。
