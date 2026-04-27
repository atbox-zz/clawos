// tools/web-search/src/lib.rs — D-01
// Brave Search API + Tavily API. Provider: "brave" (default) | "tavily"
// Secret name: "clawos-search-key" (kernel keyring or env CLAWOS_SEARCH_KEY)

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    query: String,
    #[serde(default = "default_top_k")]  top_k: usize,
    #[serde(default = "default_lang")]   lang:  String,
    #[serde(default)]                    provider: Option<String>,
}
fn default_top_k() -> usize { 5 }
fn default_lang()  -> String { "en".into() }

#[derive(Serialize)]
struct SearchResult { title: String, url: String, snippet: String, score: f64 }

#[derive(Serialize)]
struct Output {
    results: Vec<SearchResult>, query: String,
    result_count: usize, provider: String,
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid input: {e}"))?;
    if input.query.trim().is_empty() { return Err("query must not be empty".into()); }
    if input.top_k == 0 || input.top_k > 10 { return Err("top_k must be 1-10".into()); }

    let api_key = host_read_secret("clawos-search-key")
        .map_err(|e| format!("Search API key not available: {e}"))?;

    let provider = input.provider.as_deref().unwrap_or("brave");

    let results = match provider {
        "tavily" => search_tavily(&input.query, input.top_k, &api_key)?,
        _        => search_brave(&input.query, input.top_k, &input.lang, &api_key)?,
    };

    let result_count = results.len();
    serde_json::to_string(&Output { results, query: input.query, result_count, provider: provider.into() })
        .map_err(|e| e.to_string())
}

// ── Brave Search ──────────────────────────────────────────────

fn search_brave(query: &str, top_k: usize, lang: &str, api_key: &str) -> Result<Vec<SearchResult>, String> {
    let url = format!(
        "https://api.search.brave.com/res/v1/web/search?q={}&count={}&search_lang={}",
        url_encode(query), top_k, lang
    );
    let req = serde_json::json!({
        "method": "GET", "url": url,
        "headers": [
            ["Accept",               "application/json"],
            ["X-Subscription-Token", api_key]
        ]
    }).to_string();

    let resp_json = host_http_fetch(&req)?;
    let resp: serde_json::Value = serde_json::from_str(&resp_json)
        .map_err(|e| format!("Brave parse error: {e}"))?;
    let status = resp["status"].as_u64().unwrap_or(0);
    if status != 200 {
        return Err(format!("Brave HTTP {status}: {}", resp["body"].as_str().unwrap_or("")));
    }
    let body: serde_json::Value = serde_json::from_str(resp["body"].as_str().unwrap_or("{}"))
        .map_err(|e| format!("Brave body parse: {e}"))?;

    Ok(body["web"]["results"].as_array().unwrap_or(&vec![])
        .iter().take(top_k).enumerate()
        .map(|(i, item)| SearchResult {
            title:   item["title"].as_str().unwrap_or("").into(),
            url:     item["url"].as_str().unwrap_or("").into(),
            snippet: item["description"].as_str().unwrap_or("").into(),
            score:   1.0 - (i as f64 * 0.1),
        }).collect())
}

// ── Tavily Search ─────────────────────────────────────────────

fn search_tavily(query: &str, top_k: usize, api_key: &str) -> Result<Vec<SearchResult>, String> {
    let body_str = serde_json::json!({
        "api_key": api_key, "query": query,
        "max_results": top_k, "search_depth": "basic", "include_answer": false
    }).to_string();
    let req = serde_json::json!({
        "method": "POST", "url": "https://api.tavily.com/search",
        "headers": [["Content-Type","application/json"],["Accept","application/json"]],
        "body": body_str
    }).to_string();

    let resp_json = host_http_fetch(&req)?;
    let resp: serde_json::Value = serde_json::from_str(&resp_json)
        .map_err(|e| format!("Tavily parse error: {e}"))?;
    let status = resp["status"].as_u64().unwrap_or(0);
    if status != 200 {
        return Err(format!("Tavily HTTP {status}: {}", resp["body"].as_str().unwrap_or("")));
    }
    let body: serde_json::Value = serde_json::from_str(resp["body"].as_str().unwrap_or("{}"))
        .map_err(|e| format!("Tavily body parse: {e}"))?;

    Ok(body["results"].as_array().unwrap_or(&vec![])
        .iter().take(top_k)
        .map(|item| SearchResult {
            title:   item["title"].as_str().unwrap_or("").into(),
            url:     item["url"].as_str().unwrap_or("").into(),
            snippet: item["content"].as_str().unwrap_or("").into(),
            score:   item["score"].as_f64().unwrap_or(0.0),
        }).collect())
}

// ── URL encoding ──────────────────────────────────────────────

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'|b'a'..=b'z'|b'0'..=b'9'|b'-'|b'_'|b'.'|b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => { out.push('%'); out.push(hex_nib(b>>4)); out.push(hex_nib(b&0xf)); }
        }
    }
    out
}
fn hex_nib(n: u8) -> char { if n < 10 { (b'0'+n) as char } else { (b'a'+n-10) as char } }

// ── Host function declarations (wasm32) ───────────────────────

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn clawos_http_fetch(req_ptr: *const u8, req_len: usize,
                         out_ptr: *mut u8,   out_len: usize) -> i32;
    fn clawos_secrets_get(name_ptr: *const u8, name_len: usize,
                          out_ptr:  *mut u8,   out_len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
fn host_http_fetch(req: &str) -> Result<String, String> {
    let r = req.as_bytes();
    let mut out = vec![0u8; 256 * 1024];
    let n = unsafe { clawos_http_fetch(r.as_ptr(), r.len(), out.as_mut_ptr(), out.len()) };
    if n < 0 { return Err(format!("HTTP error: {n}")); }
    String::from_utf8(out[..n as usize].to_vec()).map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
fn host_read_secret(name: &str) -> Result<String, String> {
    let n = name.as_bytes();
    let mut out = vec![0u8; 4096];
    let len = unsafe { clawos_secrets_get(n.as_ptr(), n.len(), out.as_mut_ptr(), out.len()) };
    if len < 0 { return Err(format!("Secret '{name}' not found")); }
    String::from_utf8(out[..len as usize].to_vec()).map_err(|e| e.to_string())
}

// ── Native stubs (unit tests / non-wasm) ─────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn host_http_fetch(_req: &str) -> Result<String, String> {
    Ok(serde_json::json!({
        "status": 200,
        "body": r#"{"web":{"results":[
            {"title":"Stub result 1","url":"https://example.com/1","description":"First stub"},
            {"title":"Stub result 2","url":"https://example.com/2","description":"Second stub"}
        ]}}"#
    }).to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn host_read_secret(name: &str) -> Result<String, String> {
    let env = name.to_uppercase().replace('-', "_");
    std::env::var(&env).map_err(|_| format!("env {env} not set"))
}

// ── C ABI exports ─────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut v = vec![0u8; size as usize];
    let ptr = v.as_mut_ptr() as i32;
    std::mem::forget(v);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    unsafe { let _ = Vec::from_raw_parts(ptr as *mut u8, size as usize, size as usize); }
}

#[no_mangle]
pub extern "C" fn run(input_ptr: i32, input_len: i32) -> i32 {
    let input_bytes = unsafe { std::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let input_json = match std::str::from_utf8(input_bytes) { Ok(s) => s, Err(_) => return 0 };
    let result_json = match crate::run_json(input_json) {
        Ok(s)  => s,
        Err(e) => format!("{{\"error\":\"{}\"}}", e.replace('"', "'")),
    };
    let rb = result_json.as_bytes();
    let mut out = Vec::with_capacity(4 + rb.len());
    out.extend_from_slice(&(rb.len() as u32).to_le_bytes());
    out.extend_from_slice(rb);
    let ptr = out.as_mut_ptr() as i32;
    std::mem::forget(out);
    ptr
}

// ── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_query_returns_results() {
        std::env::set_var("CLAWOS_SEARCH_KEY", "test_key");
        let out = run(r#"{"query":"rust programming"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(!v["results"].as_array().unwrap().is_empty());
        assert_eq!(v["query"].as_str().unwrap(), "rust programming");
        assert!(v["result_count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn empty_query_rejected() {
        assert!(run(r#"{"query":""}"#).is_err());
    }

    #[test]
    fn top_k_zero_rejected() {
        assert!(run(r#"{"query":"test","top_k":0}"#).is_err());
    }

    #[test]
    fn top_k_over_10_rejected() {
        assert!(run(r#"{"query":"test","top_k":11}"#).is_err());
    }

    #[test]
    fn url_encode_spaces() { assert_eq!(url_encode("hello world"), "hello+world"); }

    #[test]
    fn url_encode_special() { assert_eq!(url_encode("a&b"), "a%26b"); }

    #[test]
    fn output_has_required_fields() {
        std::env::set_var("CLAWOS_SEARCH_KEY", "test_key");
        let out = run(r#"{"query":"test","top_k":2}"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["results"].is_array());
        assert!(v["result_count"].is_number());
        assert!(v["provider"].is_string());
        assert_eq!(v["provider"].as_str().unwrap(), "brave");
    }
}
