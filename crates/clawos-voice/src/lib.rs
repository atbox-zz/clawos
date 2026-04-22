// crates/clawos-voice/src/lib.rs
//
// ClawOS Voice Layer — Layer 8 (optional)
// Qwen3-TTS integration for AI-native voice I/O.
//
// Design:
//   - TTS: text → WAV bytes via Qwen3-TTS API (local or remote)
//   - STT: WAV bytes → text (future: whisper.cpp integration)
//   - Runs OUTSIDE the seccomp sandbox (needs audio syscalls)
//   - Communicates with clawos-agent via IPC (Unix socket)
//
// Activate with: cargo build --features voice
// Intentionally NOT a kernel module — audio hardware needs userspace.

#![allow(dead_code)]
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

pub mod pipeline;
pub mod stt;
pub mod tts;

// ── Config ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct VoiceConfig {
    pub backend: TtsBackend,
    /// Local Qwen3-TTS server endpoint (default: http://127.0.0.1:8020)
    pub tts_endpoint: String,
    pub sample_rate: u32,
    pub voice_id: String,
    /// Max characters per TTS request (to avoid huge audio files)
    pub max_chars: usize,
    /// Whether to stream audio chunks as they arrive
    pub streaming: bool,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            backend: TtsBackend::Qwen3Local,
            tts_endpoint: "http://127.0.0.1:8020".into(),
            sample_rate: 24000,
            voice_id: "default".into(),
            max_chars: 2000,
            streaming: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TtsBackend {
    Qwen3Local, // Local Qwen3-TTS server (from ironclaw-voice.zip)
    Qwen3Api,   // Remote API
    Stub,       // Returns empty audio (testing)
}

// ── TTS Request / Response ────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct TtsRequest {
    pub text: String,
    pub voice_id: String,
    pub format: String, // "wav" | "mp3" | "pcm"
    pub sample_rate: u32,
}

#[derive(Debug, Clone)]
pub struct TtsResponse {
    pub audio_bytes: Vec<u8>,
    pub format: String,
    pub sample_rate: u32,
    pub duration_ms: u64,
    pub char_count: usize,
}

// ── Voice Pipeline ────────────────────────────────────────────

pub struct VoicePipeline {
    config: VoiceConfig,
    client: reqwest::Client,
}

impl VoicePipeline {
    pub fn new(config: VoiceConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("HTTP client");
        Self { config, client }
    }

    /// Convert text to audio bytes.
    /// Splits long text at sentence boundaries before sending to TTS.
    pub async fn synthesise(&self, text: &str) -> Result<TtsResponse> {
        if text.trim().is_empty() {
            return Ok(TtsResponse {
                audio_bytes: vec![],
                format: "wav".into(),
                sample_rate: self.config.sample_rate,
                duration_ms: 0,
                char_count: 0,
            });
        }

        let chunks = split_at_sentences(text, self.config.max_chars);
        info!(
            chunks = chunks.len(),
            chars = text.len(),
            "TTS synthesis requested"
        );

        let mut all_audio = Vec::new();
        let start = std::time::Instant::now();

        for chunk in &chunks {
            let audio = self.synthesise_chunk(chunk).await?;
            all_audio.extend_from_slice(&audio);
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        info!(
            duration_ms,
            bytes = all_audio.len(),
            "TTS synthesis complete"
        );

        Ok(TtsResponse {
            audio_bytes: all_audio,
            format: "wav".into(),
            sample_rate: self.config.sample_rate,
            duration_ms,
            char_count: text.len(),
        })
    }

    async fn synthesise_chunk(&self, text: &str) -> Result<Vec<u8>> {
        match self.config.backend {
            //TtsBackend::Stub => {
            // Stub backend: used only in unit tests (TtsBackend::Stub is never
            // configured in production).  Return an error so callers are aware
            // TTS is not available, rather than silently returning silent audio
            // that would confuse users.
            //    anyhow::bail!(
            //        "TTS backend is Stub — configure tts_endpoint and set \
            //         backend = Qwen3Api in voice config, or set CLAWOS_TTS_ENDPOINT env var."
            //    );
            //}
            TtsBackend::Stub => {
                // 測試用：回傳空 WAV（原本 bail 改為回傳 stub_wav）
                Ok(stub_wav(self.config.sample_rate))
            }

            TtsBackend::Qwen3Local | TtsBackend::Qwen3Api => {
                let url = format!("{}/tts", self.config.tts_endpoint);
                let req = serde_json::json!({
                    "text":        text,
                    "voice_id":    self.config.voice_id,
                    "format":      "wav",
                    "sample_rate": self.config.sample_rate,
                });

                debug!(endpoint = %url, chars = text.len(), "Calling Qwen3-TTS");

                let resp = self
                    .client
                    .post(&url)
                    .json(&req)
                    .send()
                    .await
                    .context("Qwen3-TTS request failed")?;

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    anyhow::bail!(
                        "Qwen3-TTS error {}: {}",
                        status,
                        &body[..body.len().min(200)]
                    );
                }

                Ok(resp.bytes().await?.to_vec())
            }
        }
    }

    /// Send TTS output to IPC agent so it can be forwarded to the right channel.
    pub async fn speak_via_ipc(&self, session_id: &str, audio: &TtsResponse) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        const MAX_IPC_MSG_BYTES: usize = 512 * 1024; // 512 KB

        let msg = serde_json::json!({
            "id":        uuid::Uuid::new_v4().to_string(),
            "version":   1,
            "type":      "voice.audio",
            "from":      "clawos-voice",
            "to":        "clawos-agent",
            "timestamp": chrono::Utc::now().timestamp_millis(),
            "payload": {
                "session_id":  session_id,
                "format":      audio.format,
                "sample_rate": audio.sample_rate,
                "duration_ms": audio.duration_ms,
                "audio_b64":   base64_encode(&audio.audio_bytes),
            }
        });

        let msg_str = format!("{msg}\n");

        if msg_str.len() > MAX_IPC_MSG_BYTES {
            anyhow::bail!(
                "voice.audio IPC message too large: {} bytes (limit {} bytes, audio {} bytes). \
                 Split audio into shorter segments before calling speak_via_ipc.",
                msg_str.len(),
                MAX_IPC_MSG_BYTES,
                audio.audio_bytes.len(),
            );
        }
        let mut stream = tokio::net::UnixStream::connect("/var/run/clawos/ipc/agent.sock")
            .await
            .context("Cannot connect to agent IPC")?;

        stream.write_all(msg_str.as_bytes()).await?;
        Ok(())
    }
}

// ── Utility ───────────────────────────────────────────────────

/// Split text at sentence boundaries, keeping chunks under max_chars.
fn split_at_sentences(text: &str, max_chars: usize) -> Vec<String> {
    if text.len() <= max_chars {
        return vec![text.to_string()];
    }

    let mut chunks = vec![];
    let mut current = String::new();

    for sentence in text.split_inclusive(|c| c == '.' || c == '!' || c == '?' || c == '\n') {
        if current.len() + sentence.len() > max_chars && !current.is_empty() {
            chunks.push(current.trim().to_string());
            current = String::new();
        }
        current.push_str(sentence);
    }

    if !current.trim().is_empty() {
        chunks.push(current.trim().to_string());
    }

    chunks
}

/// Minimal valid WAV file with silence (44-byte header + 0 samples).
fn stub_wav(sample_rate: u32) -> Vec<u8> {
    let mut wav = vec![0u8; 44];
    // RIFF header
    wav[0..4].copy_from_slice(b"RIFF");
    let file_size: u32 = 36;
    wav[4..8].copy_from_slice(&file_size.to_le_bytes());
    wav[8..12].copy_from_slice(b"WAVE");
    wav[12..16].copy_from_slice(b"fmt ");
    wav[16..20].copy_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    wav[20..22].copy_from_slice(&1u16.to_le_bytes()); // PCM format
    wav[22..24].copy_from_slice(&1u16.to_le_bytes()); // mono
    wav[24..28].copy_from_slice(&sample_rate.to_le_bytes());
    let byte_rate = sample_rate * 2;
    wav[28..32].copy_from_slice(&byte_rate.to_le_bytes());
    wav[32..34].copy_from_slice(&2u16.to_le_bytes()); // block align
    wav[34..36].copy_from_slice(&16u16.to_le_bytes()); // bits per sample
    wav[36..40].copy_from_slice(b"data");
    wav[40..44].copy_from_slice(&0u32.to_le_bytes()); // no samples
    wav
}

fn base64_encode(data: &[u8]) -> String {
    ////use std::fmt::Write;
    // Simple base64 without external dep
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((b1 & 0xf) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_tts_returns_valid_wav() {
        let config = VoiceConfig {
            backend: TtsBackend::Stub,
            ..Default::default()
        };
        let pipeline = VoicePipeline::new(config);
        let resp = pipeline.synthesise("Hello ClawOS").await.unwrap();
        // Valid WAV starts with "RIFF"
        assert_eq!(&resp.audio_bytes[..4], b"RIFF");
    }

    #[test]
    fn sentence_splitter_keeps_short_text_intact() {
        let chunks = split_at_sentences("Hello world.", 100);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "Hello world.");
    }

    #[test]
    fn sentence_splitter_splits_long_text() {
        let long = "First sentence. ".repeat(20);
        let chunks = split_at_sentences(&long, 100);
        assert!(chunks.len() > 1);
        for c in &chunks {
            assert!(c.len() <= 120); // allow slight overflow on sentence boundary
        }
    }

    #[test]
    fn stub_wav_valid_header() {
        let wav = stub_wav(24000);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
    }
}
