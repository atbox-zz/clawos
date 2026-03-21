# IronClaw Voice Agent — 台語 AI 智能體架構規劃

> 從 Linux Kernel → IronClaw 安全架構 → 台語語音 AI 智能體
> 主要互動介面：講台灣話操控一切

---

## 一、整體系統鏈

```
┌─────────────────────────────────────────────────────────────────┐
│                     IronClaw Voice Layer                        │
│                                                                 │
│  🎙  麥克風                                                      │
│   │                                                             │
│   ▼                                                             │
│  [VAD] 靜音就跳過，偵測到語音才往下送                               │
│   │                                                             │
│   ▼                                                             │
│  [ASR: 台語辨識]  ── Whisper-TW fine-tune / CLiFT-ASR            │
│   │    文字                                                      │
│   ▼                                                             │
│  [意圖解析 + Agent]  ── Qwen3 LLM (本地 or API)                   │
│   │    指令/回應                                                 │
│   ├──────────────────────────────────┐                          │
│   ▼                                  ▼                          │
│  [IronClaw API]              [TTS: Qwen3-TTS 台語]              │
│   │ 執行安全指令                     │ 語音回應                   │
│   ▼                                  ▼                          │
│  [Kernel / 系統層]               🔊 喇叭                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 二、各層技術選型

### 2.1 語音輸入管線

#### VAD（語音活動偵測）
```
選擇：silero-vad (ONNX)
理由：
  - 可在 Rust 直接用 ort (ONNX Runtime) 呼叫
  - 極低延遲（CPU 上 < 1ms per 30ms chunk）
  - 免費、Apache 2.0

替代：webrtc-vad (更輕量，但精度較低)
```

#### ASR（台語語音辨識）
```
主要方案：Whisper Large-v3 fine-tuned on Taiwanese Hokkien
  - 基底：openai/whisper-large-v3
  - 微調資料：TAT-MOE corpus + Common Voice 台語集
  - CER ~13-25%（現有研究）

最佳現成模型：
  - CLiFT-ASR (2025, arXiv:2511.06860)  ← 最新 SOTA
    - 兩階段：先學 Tai-lo 聲調，再學漢字
    - 比 baseline 減少 24.88% CER
  - ChineseTaiwaneseWhisper (GitHub: sandy1990418)
    - 直接可用，有 REST API

整合方式（Rust）：
  - whisper.cpp binding → whisper-rs crate
  - 或透過 HTTP 呼叫本地 FastAPI 服務
```

#### 混合辨識策略（推薦）
```
輸入音訊
  │
  ├─ 偵測語言（台語 or 華語）
  │     使用 langid 或 Whisper 的 language token
  │
  ├─ 台語 → CLiFT-ASR / Whisper-TW
  └─ 華語 → Whisper / FireRedASR（備援）
```

---

### 2.2 LLM Agent 層

```
Qwen3-7B 或 Qwen3-14B（本地推理）
  - 工具：ollama 或 llama.cpp server
  - 或：Qwen API（雲端，低延遲）

系統提示（System Prompt）範例：
  你是 IronClaw 的核心智能體，名叫「鐵爪」。
  使用者用台語跟你說話，你也用台語回應。
  你可以：
  1. 查詢系統安全狀態
  2. 執行授權的核心指令
  3. 管理防火牆規則
  4. 監控系統異常
  遇到高風險操作，必須要求二次聲紋確認。

Agent 工具（Tools）：
  - get_system_status()      ← 讀取 IronClaw 安全狀態
  - list_firewall_rules()    ← 查看防火牆
  - add_firewall_rule(...)   ← 添加規則（需確認）
  - get_kernel_logs()        ← 讀取內核日誌
  - run_security_scan()      ← 觸發掃描
  - lock_system()            ← 緊急鎖定（需聲紋）
```

---

### 2.3 TTS 輸出（Qwen3-TTS）

```
API 呼叫模式（推薦，低延遲）：
  - 端點：Qwen API / DashScope
  - 模型：qwen-tts（支援閩南話）
  - 串流：接收第一個音頻封包後立即播放
  - 目標延遲：< 500ms 首包

本地模式（隱私優先）：
  - Qwen3-TTS-0.6B（效率版）
  - 用 Python FastAPI 包裝成本地服務
  - Rust 透過 HTTP 呼叫

台語聲音設定：
  - voice_id: "zh-minnan" 閩南語
  - 或 VoiceClone：錄 3 秒樣本 → 用 IronClaw 自己的聲音
  - speed: 1.0（可根據情境調整）
```

---

## 三、Rust 核心架構

### 3.1 Crate 結構

```
ironclaw-voice/
├── Cargo.toml
├── crates/
│   ├── voice-capture/          # 麥克風 + VAD
│   │   └── src/lib.rs
│   ├── asr-client/             # ASR HTTP 客戶端
│   │   └── src/lib.rs
│   ├── agent-core/             # LLM Agent + 工具
│   │   └── src/lib.rs
│   ├── tts-client/             # Qwen3-TTS 客戶端
│   │   └── src/lib.rs
│   ├── ironclaw-bridge/        # IronClaw 系統 API 橋接
│   │   └── src/lib.rs
│   └── voice-daemon/           # 主服務進程
│       └── src/main.rs
├── config/
│   └── ironclaw-voice.toml
└── scripts/
    └── setup.sh
```

### 3.2 主要資料流（Rust 程式碼）

```rust
// crates/voice-daemon/src/main.rs

use tokio::sync::mpsc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    
    let config = Config::load("config/ironclaw-voice.toml")?;
    
    // 建立管線通道
    let (audio_tx, audio_rx) = mpsc::channel::<AudioChunk>(32);
    let (text_tx, text_rx)   = mpsc::channel::<String>(16);
    let (reply_tx, reply_rx) = mpsc::channel::<String>(16);
    
    // 啟動各層服務
    tokio::spawn(voice_capture::run(audio_tx, config.vad.clone()));
    tokio::spawn(asr_client::run(audio_rx, text_tx, config.asr.clone()));
    tokio::spawn(agent_core::run(text_rx, reply_tx, config.agent.clone()));
    tokio::spawn(tts_client::run(reply_rx, config.tts.clone()));
    
    info!("🦀 IronClaw Voice Agent 啟動，等待台語指令...");
    
    // 保持主程式存活
    tokio::signal::ctrl_c().await?;
    info!("收到停止信號，關閉中...");
    Ok(())
}
```

### 3.3 語音捕捉 + VAD

```rust
// crates/voice-capture/src/lib.rs

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use tokio::sync::mpsc;

pub struct VadDetector {
    model: ort::Session,   // silero-vad ONNX
    threshold: f32,
}

impl VadDetector {
    pub fn new(model_path: &str) -> anyhow::Result<Self> {
        let model = ort::Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::All)?
            .commit_from_file(model_path)?;
        Ok(Self { model, threshold: 0.5 })
    }

    pub fn is_speech(&self, samples: &[f32]) -> bool {
        // 送入 30ms chunk (480 samples @ 16kHz)
        let input = ndarray::Array2::from_shape_vec((1, samples.len()), samples.to_vec())
            .expect("shape error");
        let outputs = self.model.run(ort::inputs!["input" => input.view()]).unwrap();
        let prob: f32 = outputs["output"].try_extract_tensor::<f32>()
            .unwrap().view()[[0, 0]];
        prob > self.threshold
    }
}

pub async fn run(tx: mpsc::Sender<AudioChunk>, config: VadConfig) -> anyhow::Result<()> {
    let host = cpal::default_host();
    let device = host.default_input_device()
|  |
    
    let vad = VadDetector::new(&config.model_path)?;
    let mut buffer: Vec<f32> = Vec::new();
    let mut speaking = false;
    let mut silence_frames = 0;

    // ... cpal stream 設置 ...
    
    // 語音端點偵測（VAD endpoint）
    // 說話開始 → 累積音訊
    // 靜音超過 800ms → 送出完整語音段
    
    Ok(())
}
```

### 3.4 ASR 客戶端

```rust
// crates/asr-client/src/lib.rs

use tokio::sync::mpsc;

#[derive(serde::Serialize)]
struct AsrRequest {
    audio_base64: String,
    language: String,   // "zh-TW-Hokkien"
    format: String,     // "wav"
}

#[derive(serde::Deserialize)]
struct AsrResponse {
    text: String,
    confidence: f32,
    language_detected: String,
}

pub async fn run(
    mut rx: mpsc::Receiver<AudioChunk>,
    tx: mpsc::Sender<String>,
    config: AsrConfig,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    
    while let Some(chunk) = rx.recv().await {
        let audio_b64 = base64::encode(&chunk.pcm_bytes);
        
        let resp: AsrResponse = client
            .post(&config.endpoint)  // 本地 Whisper-TW 服務
            .json(&AsrRequest {
                audio_base64: audio_b64,
                language: "zh-TW-Hokkien".to_string(),
                format: "wav".to_string(),
            })
            .send().await?
            .json().await?;
        
        tracing::info!("ASR 結果: {} (信心度: {:.2})", resp.text, resp.confidence);
        
        if !resp.text.is_empty() {
            tx.send(resp.text).await?;
        }
    }
    Ok(())
}
```

### 3.5 Agent 核心（工具呼叫）

```rust
// crates/agent-core/src/lib.rs

use serde_json::json;
use tokio::sync::mpsc;

const SYSTEM_PROMPT: &str = r#"
你是 IronClaw 的核心智能體，代號「鐵爪」。
系統以台語（閩南語）作為主要操作語言。
使用者用台語跟你說話，你也要用台語回應。

你能操控的工具：
- 查詢系統安全狀態
- 管理防火牆規則
- 讀取核心日誌
- 觸發安全掃描
- 緊急鎖定系統（需聲紋確認）

高風險操作規則：
1. 每次操作前，說出操作摘要讓使用者確認
2. 刪除 / 鎖定操作，必須聲紋二次驗證
3. 所有操作寫入不可竄改的審計日誌
"#;

#[derive(serde::Deserialize)]
#[serde(tag = "name", content = "parameters")]
enum AgentTool {
    #[serde(rename = "get_system_status")]
    GetSystemStatus,
    #[serde(rename = "list_firewall_rules")]
    ListFirewallRules,
    #[serde(rename = "add_firewall_rule")]
    AddFirewallRule { ip: String, port: u16, action: String },
    #[serde(rename = "run_security_scan")]
    RunSecurityScan { scope: String },
    #[serde(rename = "lock_system")]
    LockSystem { reason: String },
}

pub async fn run(
    mut rx: mpsc::Receiver<String>,
    tx: mpsc::Sender<String>,
    config: AgentConfig,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let ironclaw = ironclaw_bridge::Client::new(&config.ironclaw_socket);
    let mut history: Vec<serde_json::Value> = Vec::new();
    
    while let Some(user_text) = rx.recv().await {
        tracing::info!("使用者說: {}", user_text);
        
        history.push(json!({ "role": "user", "content": user_text }));
        
        // 呼叫 LLM（Qwen3 本地或 API）
        let response = client.post(&config.llm_endpoint)
            .json(&json!({
                "model": "qwen3-7b",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    // 加入歷史對話
                    // ...歷史訊息
                ],
                "tools": build_tools_schema(),
                "stream": false,
            }))
            .send().await?
            .json::<serde_json::Value>().await?;
        
        // 處理工具呼叫 or 直接回應
        let reply = process_response(response, &ironclaw).await?;
        
        history.push(json!({ "role": "assistant", "content": &reply }));
        tx.send(reply).await?;
    }
    Ok(())
}

fn build_tools_schema() -> serde_json::Value {
    json!([
        {
            "type": "function",
            "function": {
                "name": "get_system_status",
                "description": "查詢 IronClaw 系統安全狀態",
                "parameters": { "type": "object", "properties": {} }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "add_firewall_rule",
                "description": "新增防火牆規則",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string", "description": "目標 IP" },
                        "port": { "type": "integer" },
                        "action": { "type": "string", "enum": ["allow", "deny"] }
                    },
                    "required": ["ip", "action"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "lock_system",
                "description": "緊急鎖定系統（高風險，需聲紋）",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "reason": { "type": "string" }
                    },
                    "required": ["reason"]
                }
            }
        }
    ])
}
```

### 3.6 Qwen3-TTS 客戶端（串流播放）

```rust
// crates/tts-client/src/lib.rs

use rodio::{Decoder, OutputStream, Sink};
use tokio::sync::mpsc;

pub async fn run(
    mut rx: mpsc::Receiver<String>,
    config: TtsConfig,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let (_stream, stream_handle) = OutputStream::try_default()?;
    let sink = Sink::try_new(&stream_handle)?;

    while let Some(text) = rx.recv().await {
        tracing::info!("TTS 合成: {}", &text[..text.len().min(50)]);
        
        // 呼叫 Qwen3-TTS API
        let audio_bytes = synthesize(&client, &text, &config).await?;
        
        // 解碼並立即播放
        let cursor = std::io::Cursor::new(audio_bytes);
        let source = Decoder::new(cursor)?;
        sink.append(source);
        sink.sleep_until_end();
    }
    Ok(())
}

async fn synthesize(
    client: &reqwest::Client,
    text: &str,
    config: &TtsConfig,
) -> anyhow::Result<Vec<u8>> {
    let response = client
        .post("https://dashscope.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation")
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&serde_json::json!({
            "model": "qwen-tts",
            "input": {
                "text": text,
                "voice": "zh-minnan-female-1",  // 閩南語女聲
                "speed": 1.0
            },
            "parameters": {
                "sample_rate": 22050,
                "format": "wav"
            }
        }))
        .send().await?
        .bytes().await?;
    
    Ok(response.to_vec())
}
```

---

## 四、IronClaw 安全橋接層

```rust
// crates/ironclaw-bridge/src/lib.rs
// 與既有 IronClaw 安全架構對接

use tokio::net::UnixStream;   // 透過 Unix Socket 呼叫

pub struct Client {
    socket_path: String,
}

impl Client {
    pub fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }

    pub async fn get_system_status(&self) -> anyhow::Result<SystemStatus> {
        // 透過 IPC（Unix Domain Socket 或 D-Bus）
        // 呼叫 IronClaw 核心 API
        let stream = UnixStream::connect(&self.socket_path).await?;
        // ... 發送請求，解析回應 ...
        todo!()
    }

    pub async fn add_firewall_rule(&self, rule: FirewallRule) -> anyhow::Result<()> {
        // 需要特權，透過 IronClaw 的權限模型執行
        todo!()
    }
    
    /// 所有操作都要寫入審計日誌
    pub async fn audit_log(&self, action: &str, result: &str) -> anyhow::Result<()> {
        // 寫入 IronClaw 的不可竄改審計日誌
        todo!()
    }
}
```

---

## 五、聲紋驗證（高風險操作）

```
高風險操作流程：
  
  使用者說：「鎖定系統」
       │
       ▼
  Agent：「我聽著你想鎖定系統，這是危險的操作。
           請你再說一遍確認的口令來驗證你的聲音。」
       │
       ▼
  使用者說口令（固定短語）
       │
       ▼
  聲紋比對（voiceprint matching）
  技術：ECAPA-TDNN embeddings
        cosine similarity > 0.85 才過關
       │
       ├─ 通過 → 執行操作 + 審計日誌
       └─ 失敗 → 拒絕 + 警報 + 記錄
```

---

## 六、設定檔

```toml
# config/ironclaw-voice.toml

[vad]
model_path = "/opt/ironclaw/models/silero_vad.onnx"
threshold = 0.5
silence_ms = 800      # 靜音多久才算說完

[asr]
endpoint = "http://127.0.0.1:8765/transcribe"
language = "zh-TW-Hokkien"
model = "whisper-tw-large-v3"

[agent]
llm_endpoint = "http://127.0.0.1:11434/v1/chat/completions"  # ollama
model = "qwen3:7b"
ironclaw_socket = "/run/ironclaw/core.sock"
history_len = 10      # 保留幾輪對話

[tts]
provider = "qwen-api"  # 或 "local"
api_key_env = "QWEN_API_KEY"
voice = "zh-minnan-female-1"
speed = 1.0
local_endpoint = "http://127.0.0.1:8766/synthesize"

[security]
voiceprint_threshold = 0.85
high_risk_actions = ["lock_system", "delete_rule", "kernel_modify"]
audit_log_path = "/var/log/ironclaw/voice_audit.log"
```

---

## 七、部署架構

```
┌─────────────────────────────────────────────┐
│            IronClaw Host                    │
│                                             │
│  ┌─────────────────────────────────┐        │
│  │     ironclaw-voice (Rust)       │        │
│  │  voice-daemon  (main thread)    │        │
│  └────────────┬────────────────────┘        │
│               │ Unix Socket / HTTP          │
│  ┌────────────┴────────────────────┐        │
│  │  Python 微服務（AI 模型）         │        │
│  │  ├─ ASR: Whisper-TW (port 8765) │        │
│  │  └─ TTS: Qwen3-TTS  (port 8766) │        │
│  └─────────────────────────────────┘        │
│               │                             │
│  ┌────────────┴────────────────────┐        │
│  │  ollama (LLM)  (port 11434)     │        │
│  │  └─ qwen3:7b                    │        │
│  └─────────────────────────────────┘        │
│               │                             │
│  ┌────────────┴────────────────────┐        │
│  │  IronClaw 核心 (既有架構)        │        │
│  │  ├─ Kernel Module               │        │
│  │  ├─ Security Policy Engine      │        │
│  │  └─ Audit Subsystem             │        │
│  └─────────────────────────────────┘        │
└─────────────────────────────────────────────┘
```

---

## 八、開發里程碑

| 階段 | 內容                | 工具               |
| ----| --------------------| ------------------|
| M1  | 麥克風捕捉 + VAD     | cpal + silero-vad |
| M2  | 台語 ASR 接通        | Whisper-TW REST   |
| M3  | LLM Agent 基本對話   | Qwen3 + ollama    |
| M4  | IronClaw 橋接（唯讀） | Unix Socket IPC   |
| M5  | Qwen3-TTS 台語回應   | Qwen API 串流       |
| M6  | 工具呼叫（查狀態）    | Function calling  |
| M7  | 聲紋驗證             | ECAPA-TDNN        |
| M8  | 高風險操作 + 審計日誌 | IronClaw 審計系統     |
| M9  | 本地 TTS（離線）      | Qwen3-TTS-0.6B 本地 |

---

## 九、關鍵 Crates

```toml
[dependencies]
# 音訊
cpal = "0.15"            # 跨平台音訊 I/O
rodio = "0.19"           # 音訊播放
hound = "3.5"            # WAV 編解碼

# AI 模型推理
ort = "2.0"              # ONNX Runtime（VAD）
whisper-rs = "0.11"      # Whisper bindings（備用）

# 網路
reqwest = { version = "0.12", features = ["json", "stream"] }
tokio = { version = "1", features = ["full"] }

# 序列化
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"

# 系統
nix = "0.29"             # Unix 系統呼叫
tracing = "0.1"
tracing-subscriber = "0.3"
anyhow = "1"
thiserror = "2"
config = "0.14"          # 設定檔讀取
```
