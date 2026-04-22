// crates/clawos-voice/src/pipeline.rs
//
// Voice pipeline coordinator — drives TTS+STT in tandem.
// Receives text from clawos-agent IPC → synthesises audio → plays back.
// Receives audio from microphone → transcribes → sends to agent as chat message.

use crate::stt::SttEngine;
use crate::{VoiceConfig, VoicePipeline};
use anyhow::Result;
use tracing::{debug, info};

pub struct VoiceCoordinator {
    pipeline: VoicePipeline,
    stt: SttEngine,
}

impl VoiceCoordinator {
    pub fn new(config: VoiceConfig) -> Self {
        Self {
            pipeline: VoicePipeline::new(config),
            stt: SttEngine::new(),
        }
    }

    /// Text-in → audio-out.
    /// Called when agent IPC delivers a text reply to speak aloud.
    pub async fn speak(&self, session_id: &str, text: &str) -> Result<()> {
        debug!(chars = text.len(), "Voice pipeline: text → TTS");
        let audio = self.pipeline.synthesise(text).await?;
        info!(
            duration_ms = audio.duration_ms,
            bytes = audio.audio_bytes.len(),
            "TTS complete"
        );

        // In production: play via cpal audio device (when feature=voice)
        // For now: forward to IPC for delivery to appropriate channel
        self.pipeline.speak_via_ipc(session_id, &audio).await
    }

    /// Audio-in → text-out.
    /// Called when microphone capture is enabled (P5).
    pub async fn transcribe_and_send(&self, _wav: &[u8]) -> Result<String> {
        self.stt.transcribe(_wav).await
    }
}
