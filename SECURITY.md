# 安全與資料邊界

此專案是本機 Lab。預設只綁定 localhost，沒有攻擊執行器、回應執行器或外部工具憑證。只使用你有授權的測試資料與環境。

- 不要提交 `.env`、token、真實事件、主機證據或客戶資料；`.gitignore` 已排除預設資料庫與環境設定。
- 原始 payload 會儲存於 SQLite 的 details；沒有自動遮罩、加密、刪除／retention 或備份策略。
- API key 為共用 Lab key。無 RBAC、可驗證的 reviewer 身分、雙人核准、TLS、rate limit 或 request-size limit。
- `/docs` 與 `/health` 不需要驗證；資料 endpoints 皆需要 key。
- 事件描述、IOC、工具回應均屬不可信資料。後續 Agent 不得從這些文字取得執行授權。
- 公開 issue 請只附合成重現資料，不要放密碼或真實安全日誌。

正式部署前需完成 docs/roadmap.md 的身分、稽核、隔離與資料保護要求，以及第三方工具版本與授權審查。
