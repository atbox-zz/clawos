// tools/summarise/src/lib.rs
//
// Summarise tool: reads a file from ClawFS workspace and
// returns an LLM-generated summary.
// Capabilities: FsRead, LlmComplete

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    /// ClawFS workspace path to summarise
    path:   Option<String>,
    /// Or inline text to summarise
    text:   Option<String>,
    #[serde(default = "default_style")]
    style:  String,    // "bullet" | "paragraph" | "tldr"
    #[serde(default = "default_max_words")]
    max_words: u32,
}

fn default_style()     -> String { "paragraph".into() }
fn default_max_words() -> u32    { 150 }

#[derive(Serialize)]
struct Output {
    summary:    String,
    word_count: usize,
    source:     String,
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid input: {e}"))?;

    // Get source text
    let (text, source) = if let Some(path) = &input.path {
        let content = host_clawfs_read(path)?;
        (content, path.clone())
    } else if let Some(text) = input.text {
        (text, "inline".into())
    } else {
        return Err("Provide either 'path' or 'text'".into());
    };

    if text.len() > 100_000 {
        return Err("Text too long (max 100KB)".into());
    }

    // Build prompt
    let style_instruction = match input.style.as_str() {
        "bullet"    => format!("Summarise in bullet points. Max {} words total.", input.max_words),
        "tldr"      => format!("Write a single TL;DR sentence under {} words.", input.max_words / 3),
        _           => format!("Write a concise paragraph summary. Max {} words.", input.max_words),
    };

    let prompt = format!(
        "You are a precise summarisation assistant.\n{style_instruction}\n\nText to summarise:\n---\n{text}\n---"
    );

    let req_json = serde_json::json!({
        "messages": [
            { "role": "user", "content": prompt }
        ],
        "max_tokens": 512,
        "temperature": 0.3
    });

    let resp_json = host_llm_complete(&req_json.to_string())?;
    let resp: serde_json::Value = serde_json::from_str(&resp_json)
        .map_err(|e| format!("LLM parse error: {e}"))?;

    let summary = resp["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("(no summary)")
        .trim()
        .to_string();

    let word_count = summary.split_whitespace().count();

    let output = Output { summary, word_count, source };
    serde_json::to_string(&output).map_err(|e| e.to_string())
}

// Host function stubs
#[cfg(not(target_arch = "wasm32"))]
fn host_clawfs_read(path: &str) -> Result<String, String> {
    // Unit test stub — in real WASM this calls clawos:runtime/clawfs.read-file
    Ok(format!("Stub file content for: {path}"))
}

#[cfg(not(target_arch = "wasm32"))]
fn host_llm_complete(_req_json: &str) -> Result<String, String> {
    Ok(serde_json::json!({
        "choices": [{"message": {"content": "This is a stub summary."}}]
    }).to_string())
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn clawos_clawfs_read(path_ptr: *const u8, path_len: usize,
                          out_ptr: *mut u8, out_len: usize) -> i32;
    fn clawos_llm_complete(req_ptr: *const u8, req_len: usize,
                           out_ptr: *mut u8, out_len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
fn host_clawfs_read(path: &str) -> Result<String, String> {
    let p = path.as_bytes();
    let mut out = vec![0u8; 1024 * 1024]; // 1MB max
    let n = unsafe { clawos_clawfs_read(p.as_ptr(), p.len(), out.as_mut_ptr(), out.len()) };
    if n < 0 { return Err(format!("ClawFS read error: {n}")); }
    String::from_utf8(out[..n as usize].to_vec()).map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
fn host_llm_complete(req_json: &str) -> Result<String, String> {
    let r = req_json.as_bytes();
    let mut out = vec![0u8; 64 * 1024];
    let n = unsafe { clawos_llm_complete(r.as_ptr(), r.len(), out.as_mut_ptr(), out.len()) };
    if n < 0 { return Err(format!("LLM error: {n}")); }
    String::from_utf8(out[..n as usize].to_vec()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarise_inline_text() {
        let out = run(r#"{"text":"The quick brown fox jumps over the lazy dog. This is a test."}"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["summary"].as_str().is_some());
    }

    #[test]
    fn fails_without_path_or_text() {
        assert!(run("{}").is_err());
    }
}

// ── C ABI exports (required by worker/mod.rs host caller) ────────────────
// worker calls: alloc(size) -> ptr, run(ptr, len) -> result_ptr, dealloc(ptr, size)
// Result format: [4 bytes LE u32 length][JSON bytes]

#[cfg(target_arch = "wasm32")]
static mut HEAP: Vec<u8> = Vec::new();

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut v = vec![0u8; size as usize];
    let ptr = v.as_mut_ptr() as i32;
    std::mem::forget(v);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, size as usize, size as usize);
    }
}

#[no_mangle]
pub extern "C" fn run(input_ptr: i32, input_len: i32) -> i32 {
    let input_bytes = unsafe {
        std::slice::from_raw_parts(input_ptr as *const u8, input_len as usize)
    };
    let input_json = match std::str::from_utf8(input_bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let result_json = match crate::run_json(input_json) {
        Ok(s)  => s,
        Err(e) => format!("{{\"error\":\"{}\"}}", e.replace('"', "'")),
    };

    let result_bytes = result_json.as_bytes();
    let total = 4 + result_bytes.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(result_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(result_bytes);

    let ptr = out.as_mut_ptr() as i32;
    std::mem::forget(out);
    ptr
}
