# API 與資料契約

狀態：設計草案，包含現有PoC相容介面。實際產品／認證／部署位址待確認；本文件不建立額外服務或schema migration。

## 來源 HTTP API

| 方法與路徑 | Profile | 目的 |
| --- | --- | --- |
| POST /api/v1/logs/fortinet | fortinet | Fortinet Log接收與正規化 |
| POST /api/v1/logs/paloalto | paloalto | Palo Alto Log接收與正規化 |
| POST /api/v1/logs/cisco | cisco | Cisco Log接收與正規化 |
| POST /api/v1/logs/windows | windows | Windows／AD agent輸出 |
| POST /api/v1/logs/linux | linux | Linux／應用Log |
| POST /api/v1/logs/aws | aws | AWS forwarder輸出 |
| POST /api/v1/logs/kubernetes | kubernetes | 容器／K8s agent輸出 |
| GET /api/v1/sources | 全部 | 管理者查看來源設定 |

既有介面接受application/json物件或物件陣列、application/x-ndjson、text/plain逐行資料；AWS另外接受CloudTrail的Records陣列。多行stack trace、XML／EVTX二進位檔、壓縮CloudWatch subscription envelope須有前置adapter，不能視為已支援。

目前PoC每個HTTP body上限2 MiB、每raw字串65,536字元、來源API每批1–5000筆；Syslog frame上限65,536 bytes。這些是實作限制，正式批次與大小政策在流量盤點後決定。

## 成功、錯誤與重試

| HTTP狀態 | 現有PoC語義 | 呼叫端處理原則 |
| --- | --- | --- |
| 200 | 同步保存raw與事件完成；回accepted、records | 可結束該次重試 |
| 401 | 要求key但key缺失／錯誤 | 修正認證，不無限重送 |
| 403 | 來源停用或peer不在允許範圍 | 查來源設定與實際網路路徑 |
| 409 | 同一去重ID帶入不同內容，整批rollback | 檢查ID生成及payload變更 |
| 413 | request body過大 | 減少批次／調整上游輸出 |
| 422 | 輸入結構、字串限制等不合法 | 修正格式；原始資料由發送端保留 |
| 5xx／網路失敗 | 未能確認接收結果 | 以穩定ID重試，避免產生不同身份 |

PoC的解析失敗與API格式錯誤不同：合法raw紀錄即使parser失敗仍可回200，並保存parser_status=error。未來非同步版本可能用202表示「已持久化排隊但未完成解析」；需另定status查詢、重試與版本升級，現有API尚未提供202流程。429／Retry-After、per-source rate limit與backpressure也屬後續設計。

來源API的Idempotency-Key搭配peer、批內序號產生去重ID；相同內容沒有key時會視為新的發生事件。現有/logs則以(source, record_id)去重。正式模型應使用穩定device/source identity加原始event ID或collector ID，避免來源IP改變破壞重送語義。

## Raw envelope

| 欄位 | 語義 | PoC／目標差距 |
| --- | --- | --- |
| id／raw_id | 原始紀錄識別 | PoC使用id；目標契約需確定名稱與引用方式 |
| source | 來源profile，例如fortinet | 已有 |
| device_id／site_id | 實際設備與站點識別 | 待資產盤點與實作 |
| received_at | 收集系統接收時間，含時區 | 已有 |
| peer | receiver觀察到的來源位址 | 已有；不等同設備自述host |
| transport／format | 接入協定與格式提示 | 已有 |
| raw | 原始Log文字 | 已有；JSON物件入口會重新序列化 |
| raw_base64 | 原始bytes的可逆表示 | Syslog／collector具備；並非所有HTTP入口都具備 |
| vendor／product／asset_type | 設定或解析得到的來源metadata | 已有；信任來源需明確標示 |
| parser_status／parser_version | 解析結果與規則版本 | status已有；完整parser版本追蹤待實作 |

若法證需求要求逐byte一致，必須保存原始傳輸payload或bytes/hash/reference；不能將目前JSON重新序列化結果宣稱為逐byte證據。

## Normalized event

以source profile為共通入口，normalizer輸出共同schema。缺欄為null、未知格式保留raw，不能捏造IP、使用者或攻擊分類。

| 欄位群 | 欄位 | 設計原則 |
| --- | --- | --- |
| 版本／來源 | schema_version、normalizer、source | profile-v1與schema版本可追溯 |
| 時間 | timestamp、timestamp_basis | event或received；設備時間不能推定年份／時區 |
| 身分 | host、user、vendor、product | 保留來源語義，不能當成已驗證主體 |
| 行為 | category、action、event_code、outcome | 不同來源映射到一致型別，仍保留來源欄位 |
| 網路 | source_ip、destination_ip、source_port、destination_port、protocol | IP合法性與port範圍檢查 |
| 分級 | severity、parser_status | severity保留調查用途，不代表確認攻擊 |
| 容器 | namespace、pod、container | 來源具metadata才填入 |
| 追溯 | raw reference、normalizer版本、ingest ID | PoC的normalized嵌於Log／Event.details；正式欄位待定 |

目前schema_version=1.0及normalizer名稱是PoC版號；不代表完整ECS／OCSF相容。是否選ECS／OCSF或建立映射，由既有SIEM與分析需求決定。

## 下游邏輯介面

以下是設計契約，尚未實作為新HTTP endpoint：

| 產出物 | 最小資訊 | 使用方 |
| --- | --- | --- |
| Finding／Alert | alert_id、rule_id/version、event references、severity、technique（可空） | 偵測／案件 |
| Investigation case | case_id、狀態、owner、alert references、timeline | 調查協作 |
| Evidence reference | 原始系統、object ID、時間、hash（適用時）、存取政策 | 調查與報告 |
| Response proposal | case_id、action、target、理由、影響、回復計畫 | 人工核准 |
| Approval／execution audit | 可驗證主體、policy、時效、執行結果、回復紀錄 | 稽核與受控adapter |
| Purple Team run | run_id、授權範圍、technique、預期／觀察結果、清理紀錄 | 偵測覆蓋評估 |

## 版本與相容性

新增可選欄位優先維持舊consumer相容；欄位改義、改型別、認證或成功語義變更需新版本或明確migration。Raw保存與parser版本讓事件可重新解析；重處理應記錄replay ID及輸出版本，避免默默覆寫調查證據。正式Schema Registry、topic名稱、index mapping與migration方式均待平台選型後實作。
