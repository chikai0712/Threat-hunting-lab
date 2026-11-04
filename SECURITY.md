# 安全與資料邊界

此專案是本機 Lab。v0.3 的環境設定啟動器預設監聽全部 IPv4 介面，但七類來源預設留白停用，沒有攻擊執行器、回應執行器或外部工具憑證。只使用你有授權的測試資料與環境。

- 不要提交 `.env`、token、真實事件、主機證據或客戶資料；`.gitignore` 已排除預設資料庫與環境設定。
- 原始 payload／Log 會儲存於 SQLite，collector outbox 也包含原文；沒有自動遮罩、加密、刪除／retention 或備份策略。
- API key 為共用 Lab key。無 RBAC、可驗證的 reviewer 身分、雙人核准或 rate limit。HTTP body 限制為 2 MiB；API 的遠端 HTTPS 需另配置反向代理。Syslog collector 可提供伺服器 TLS，但未實作 mTLS。
- `/docs` 與 `/health` 不需要驗證；查詢與管理 endpoints 皆需要 key；`/api/v1/logs/<source>` 預設採設定的 socket peer IP allowlist，設 `SOURCE_PUSH_REQUIRE_TOKEN=true` 可再要求 key。
- 事件描述、IOC、工具回應均屬不可信資料。後續 Agent 不得從這些文字取得執行授權。
- 公開 issue 請只附合成重現資料，不要放密碼或真實安全日誌。

正式部署前需完成 docs/roadmap.md 的身分、稽核、隔離與資料保護要求，以及第三方工具版本與授權審查。

- Syslog listener 預設只允許 loopback；對外接設備需明確設定 bind 與 allowed CIDRs，並控管主機防火牆。來源 IP 不能替代強身分認證。
- Outbox 與中央 SQLite 尚無容量上限／retention／自動清理，需監控磁碟空間；UDP 與 TCP Syslog 都不提供應用層 durable acknowledgement。
- CloudWatch collector 使用 AWS SDK credential chain 與最小權限 `logs:FilterLogEvents`；不將雲端憑證寫入設定檔。

- `threat-lab` 停用 proxy header 信任；自訂 Uvicorn 指令必須加 `--no-proxy-headers`，避免代理 header 改寫來源判斷。
- IP-only PUSH 僅適用可控網段；特別是 UDP 的來源 IP 可能被偽造。Syslog profile 的 IP 不得重疊，設定衝突會拒絕啟動。
