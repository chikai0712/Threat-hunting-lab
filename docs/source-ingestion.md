# 來源接入設計

狀態：來源與設定契約草案；實際 IP、型號、韌體、轉送條件待確認。

## 接入矩陣

| Profile | 來源 | 優先接法 | 需取得的樣本／資訊 |
| --- | --- | --- | --- |
| fortinet | FortiGate／Fortinet | Syslog；支援時 HTTP relay | 型號／FortiOS、KV或CEF格式、traffic／event類型 |
| paloalto | Palo Alto PAN-OS | Syslog／CEF／HTTP relay | PAN-OS、預設CSV或自訂欄位、Traffic／Threat／System |
| cisco | Switch／Router／Firewall | Syslog | IOS／IOS-XE／NX-OS／ASA版本、sequence與timestamp格式 |
| windows | Windows／AD | Windows agent → HTTP | OS、channel、EventID、agent輸出格式、AD／Sysmon需求 |
| linux | Linux／應用程式 | rsyslog／agent／檔案轉送 → PUSH | distro、journald／檔案、輪替、多行及encoding |
| aws | CloudTrail／CloudWatch等 | 受控forwarder → HTTP；必要時PULL | 帳戶／區域、log group／S3、IAM、egress與事件格式 |
| kubernetes | 容器／叢集 | Fluent Bit等 → HTTP | runtime、CRI／Docker、audit／Falco、metadata與node IP |

設備型號／軟體種類可以擴充 profile；獨立 API 表示獨立來源契約及 normalizer，不要求每個來源部署不同服務。

## 環境設定模型

| 變數 | 語義 | 狀態／原則 |
| --- | --- | --- |
| LISTEN_IP | 接收伺服器監聽位址 | 實際網卡／網段待確認 |
| HTTP_PORT | HTTP PUSH與管理API port | PoC為8000；環境定案後確認 |
| SYSLOG_ENABLED / SYSLOG_PORT | 是否啟用共用Syslog接收器 | PoC為5514 TCP／UDP；非固定正式規格 |
| FORTINET_IPS | Fortinet設備／forwarder的可見來源IP | 空白停用 |
| PALOALTO_IPS | Palo Alto來源IP | 空白停用 |
| CISCO_IPS | Cisco來源IP | 空白停用 |
| WINDOWS_IPS | Windows／AD agent來源IP | 空白停用 |
| LINUX_IPS | Linux／應用agent來源IP | 空白停用 |
| AWS_IPS | AWS forwarder可見egress IP | 不是「所有AWS服務IP」 |
| KUBERNETES_IPS | K8s agent／egress來源IP | 確認NAT後可見位址 |
| SOURCE_PUSH_REQUIRE_TOKEN | HTTP PUSH是否額外要求key | PoC選項；正式認證待定 |

IP欄位支援單一IP、逗號分隔多IP、CIDR；這是接收側路由與存取設定，不是遠端修改設備的命令。設備仍需啟用Log forwarding並指向接收器實際位址。

## 來源辨識順序

1. HTTP先由固定endpoint選profile，再用可信socket peer驗證來源；不能讓body或未驗證的X-Forwarded-For自行指定授權IP。
2. 共用Syslog listener依socket peer匹配profile；重疊範圍導致多義時不應任選一個，PoC採拒絕啟動。
3. 設備自述hostname與collector看到的peer分別保存。正式device_id、site_id、租戶識別在資產盤點後定義。
4. 未知來源與已知來源的未知格式要分開：未授權來源拒收；已授權但無法解析的Log保存原文並標示狀態。

## NAT、relay與代理

| 情境 | 可行方式 | 待確認事項 |
| --- | --- | --- |
| 原始設備IP可見 | 共用Syslog port，以IP路由 | ingress規則、來源穩定性 |
| 不同來源共用NAT IP | 使用不同HTTP endpoint，或設計獨立listener | 僅靠IP無法分辨Syslog廠牌 |
| 中央Syslog relay | relay端分流，或使用有驗證的來源metadata | relay信任、原始device身份、格式 |
| HTTP reverse proxy | 決定TLS終結與可信代理協定 | 現有PoC停用forwarded-header信任 |
| Docker Desktop／container NAT | 優先驗證來源IP是否保留 | 若被改寫，改採合適網路部署形態 |

獨立listener／可信relay metadata是待實作選項，不是現有環境變數已支援的功能。

## 正規化pipeline

協定解封裝 → raw保存 → 選profile／normalizer版本 → 欄位解析 → 型別／時間檢查 → 共同schema → 寫入事件及解析狀態。

每個normalizer需定義支援的來源版本、樣本、欄位映射、缺欄行為、時間處理及未知格式結果。Palo Alto自訂CSV、Cisco特定prefix、Windows巢狀事件與不同CRI格式，不應僅因廠牌名稱相同就視為全面相容。

## 後續新增來源流程

建立設備盤點項 → 取得去識別化樣本 → 選現有profile或提出新profile → 定義mapping／source identity → 建立契約與負向案例 → 隔離測試環境驗證 → 更新相容性矩陣 → 排入部署。

目前保留PoC中的七個endpoint。正式來源登錄、更多實例或多租戶需求，依 [環境確認表](environment-checklist.md) 結果再設計。
