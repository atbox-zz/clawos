// tools/file-read/src/lib.rs

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    path:       String,
    start_line: Option<usize>,
    end_line:   Option<usize>,
    #[serde(default = "default_encoding")]
    encoding:   String,
}
fn default_encoding() -> String { "utf8".into() }

#[derive(Serialize)]
struct Output {
    content:    String,
    line_count: usize,
    size_bytes: usize,
    path:       String,
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid input: {e}"))?;

    if input.path.contains("..") || input.path.contains('\0') {
        return Err("Invalid path: path traversal not allowed".into());
    }

    let content = host_clawfs_read(&input.path)?;
    let size_bytes = content.len();

    let text = if input.encoding == "hex" {
        content.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    } else {
        String::from_utf8_lossy(&content).into_owned()
    };

    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();

    let sliced = match (input.start_line, input.end_line) {
        (Some(s), Some(e)) => {
            let s = s.saturating_sub(1).min(total_lines);
            let e = e.min(total_lines);
            lines[s..e].join("\n")
        }
        (Some(s), None) => {
            let s = s.saturating_sub(1).min(total_lines);
            lines[s..].join("\n")
        }
        _ => text.clone(),
    };

    let out = Output {
        content:    sliced,
        line_count: total_lines,
        size_bytes,
        path:       input.path,
    };
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn host_clawfs_read(_path: &str) -> Result<Vec<u8>, String> {
    Ok(b"stub file content\nline 2\nline 3".to_vec())
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn clawos_clawfs_read(path_ptr: *const u8, path_len: usize,
                          out_ptr: *mut u8, out_len: usize) -> i32;
}
#[cfg(target_arch = "wasm32")]
fn host_clawfs_read(path: &str) -> Result<Vec<u8>, String> {
    let p = path.as_bytes();
    let mut out = vec![0u8; 10 * 1024 * 1024]; // 10MB max
    let n = unsafe { clawos_clawfs_read(p.as_ptr(), p.len(), out.as_mut_ptr(), out.len()) };
    if n < 0 { return Err(format!("ClawFS read error: {n}")); }
    Ok(out[..n as usize].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_full_file() {
        let out = run(r#"{"path":"/workspace/test.txt"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["line_count"].as_u64().unwrap() > 0);
    }
    #[test]
    fn path_traversal_blocked() {
        assert!(run(r#"{"path":"../etc/passwd"}"#).is_err());
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
