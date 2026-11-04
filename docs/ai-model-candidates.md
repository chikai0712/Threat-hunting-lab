# Hugging Face 模型候選矩陣

狀態：研究候選，未選型。來源為使用者於2026-11-04提供的研究筆記；原筆記未提供完整模型URL。本輪未線上核對模型卡、權重可用性、模型名稱、能力或授權，因此下列名稱僅作搜尋／盤點線索，不是可直接下載的精確repo ID。

## 候選與評估用途

| 筆記中的名稱 | 擬評估類型 | 平台任務 | 查核重點 |
| --- | --- | --- | --- |
| Cisco Foundation-Sec-8B／Instruct／Reasoning | 資安生成／推理模型系列 | SOC triage、摘要、調查與RCA草稿 | 是否存在對應variant、base/instruct差異、授權與chat template |
| MiST-8B | 資安生成模型候選 | CTI、CVE/CWE、ATT&CK與hunt假設 | 作者／repo、模型卡、語言、benchmark與使用界線 |
| CyberPal 2.0／CyberPal2.0-20B | 資安生成模型候選 | SOC／IR與防禦建議 | 精確版本、資源、tool calling是否實測 |
| SecBERT | encoder／下游分類基礎候選 | 資安文字分類、實體／特徵抽取 | 是否需task head、標籤資料與fine-tuning；非直接聊天替代 |
| LAnoBERT | 日誌異常研究候選 | 系統Log序列異常 | 精確checkpoint、訓練資料、輸入窗口與新來源適配 |
| CIRCL ATT&CK Classifier | 分類候選 | CVE描述→可能techniques | 精確repo、標籤／ATT&CK版本、multi-label指標 |
| ModernBERT Phishing Detector | 郵件分類候選 | 郵件／釣魚finding | 名稱不唯一，需作者與repo；郵件來源接入另列範圍 |
| TTPXHunter | TTP抽取候選 | Threat report→ATT&CK候選 | 產物是模型或pipeline、依賴、標籤版本 |
| BGE-M3 | embedding候選 | Runbook／CTI／歷史RCA檢索 | revision、語言、維度與embedding模式支援 |
| Qwen3-8B | 通用生成基準候選 | 與資安模型在相同任務比較 | variant、模板、推理模式、授權與資源 |

上述用途是待測試的工作假設。原筆記中的基礎模型、Apache 2.0／自訂授權及benchmark敘述尚未核實；不將其寫入正式license決策或性能承諾。筆記提到的Windows 11、64GB RAM與Intel Ultra 7也不是本專案已確認的部署環境。

## 每個候選必填的 registry 欄位

| 欄位 | 本輪值／要求 |
| --- | --- |
| candidate_id／task_type | 使用內部代號；generation、embedding、classification、anomaly分開 |
| publisher／repo_id／model_card_url | 待查核；不以顯示名稱猜測repo |
| revision／artifact hash | 待固定不可變版本 |
| license／base model license | 待查核原始條款、使用限制與衍生權重條件 |
| artifact type／tokenizer／template | 確認base或instruct、輸入輸出與模板 |
| runtime／precision／quantization | 待硬體與相容性實測；量化也需重評估 |
| context／output／batch limits | 依模型限制與服務設定記錄 |
| resource profile | GPU型號、VRAM、CPU/RAM、吞吐與延遲實測 |
| allowed data scope／hosting | 本機、內網或受管服務；資料可處理範圍 |
| evaluation report／status | candidate → verified → evaluated → selected；本輪均為candidate |

正式引入時檢查模型artifact、依賴與載入方式；若需要自訂remote code，另行檢視並固定來源版本，不能預設開啟。權重可取得不代表已允許所有企業使用方式。

## 比較順序草案

1. **先建共同評估集與baseline**：規則／人工摘要流程，再與Qwen3-8B候選及資安生成模型比較。
2. **Triage／RAG**：Foundation-Sec系列與MiST候選，在相同證據、檢索資料、prompt版本與輸出限制下比較；BGE-M3獨立評估檢索品質。
3. **異常偵測**：先量測各來源正常分布與統計baseline，再測LAnoBERT或適合該事件格式的模型。
4. **專項任務**：依實際CTI／郵件資料及標籤需求評估SecBERT、TTPXHunter、ATT&CK／phishing分類候選；CyberPal候選依資源條件納入。

這是研究順序，不是已授權的下載或執行排程。模型最終選擇由環境盤點與 [評估結果](ai-contracts-evaluation.md) 決定。
