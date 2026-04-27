// crates/clawos-voice/src/stt.rs
//
// Speech-to-text — P5 (whisper.cpp integration)
// P3/P4: stub that returns empty transcription.

use anyhow::Result;

pub struct SttEngine;

impl SttEngine {
    pub fn new() -> Self {
        Self
    }

    /// Transcribe WAV bytes to text.
    /// P5: wire to whisper.cpp via FFI or subprocess.
    pub async fn transcribe(&self, _wav_bytes: &[u8]) -> Result<String> {
        tracing::warn!("STT not yet implemented (P5 — whisper.cpp)");
        Ok(String::new())
    }
}
