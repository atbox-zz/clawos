// crates/clawos-agent/src/agent/gate.rs
//
// Gate Validator — G-01
// Checks all conditions for phase transitions:
//   P1_TO_P2: 8 frozen specs, vault entries, tests green
//   P2_TO_P3: cargo clippy zero warnings, seccomp live, cgroups configured
//   P3_TO_P4: all tools loaded, channels connected, migration done
//   P4_TO_RELEASE: benchmark ≥ 80%, security report PASS, ISO < 128MB

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GateId {
    P1ToP2,
    P2ToP3,
    P3ToP4,
    P4ToRelease,
}

impl GateId {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "P1_TO_P2" | "P1→P2" => Some(GateId::P1ToP2),
            "P2_TO_P3" | "P2→P3" => Some(GateId::P2ToP3),
            "P3_TO_P4" | "P3→P4" => Some(GateId::P3ToP4),
            "P4_TO_RELEASE" | "P4→RELEASE" => Some(GateId::P4ToRelease),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub blocker: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub gate: String,
    pub passed: bool,
    pub checks: Vec<GateCheck>,
    pub blockers: usize,
}

// ── Gate Runner ───────────────────────────────────────────────

pub async fn run_gate(gate: GateId) -> GateResult {
    let (gate_name, checks) = match gate {
        GateId::P1ToP2 => ("P1→P2", check_p1_to_p2().await),
        GateId::P2ToP3 => ("P2→P3", check_p2_to_p3().await),
        GateId::P3ToP4 => ("P3→P4", check_p3_to_p4().await),
        GateId::P4ToRelease => ("P4→RELEASE", check_p4_to_release().await),
    };

    let blockers = checks.iter().filter(|c| c.blocker && !c.passed).count();
    let passed = blockers == 0;

    if passed {
        info!(gate = gate_name, "Gate PASSED ✅");
    } else {
        warn!(gate = gate_name, blockers, "Gate BLOCKED ❌");
    }

    GateResult {
        gate: gate_name.into(),
        passed,
        checks,
        blockers,
    }
}

// ── P1 → P2: All frozen specs + vault ────────────────────────

async fn check_p1_to_p2() -> Vec<GateCheck> {
    let mut checks = vec![];
    let _specs_dir = Path::new("specs/p1");

    let required_specs = [
        ("P1.1", "wit/clawos.wit"),
        ("P1.2", "specs/p1/seccomp-whitelist.json"),
        ("P1.3", "specs/p1/ebpf-event-structs.rs"),
        ("P1.4", "specs/p1/clawfs-spec.json"),
        ("P1.5", "specs/p1/resource-quotas.json"),
        ("P1.6", "specs/p1/apparmor-spec.json"),
        ("P1.7", "specs/p1/ipc-protocol.json"),
        ("P1.8", "specs/p1/api-surface.json"),
    ];

    for (spec_id, path) in &required_specs {
        let exists = Path::new(path).exists();
        checks.push(GateCheck {
            name: format!("{spec_id} spec file present"),
            passed: exists,
            detail: if exists {
                path.to_string()
            } else {
                format!("MISSING: {path}")
            },
            blocker: true,
        });

        if exists {
            // Check frozen flag in JSON specs
            if path.ends_with(".json") {
                let frozen = check_frozen_flag(path);
                checks.push(GateCheck {
                    name: format!("{spec_id} marked frozen"),
                    passed: frozen,
                    detail: if frozen {
                        "frozen: true".into()
                    } else {
                        "frozen flag missing or false".into()
                    },
                    blocker: true,
                });
            }
        }
    }

    // Vault directory must exist
    let vault_exists = Path::new("/var/lib/clawos/vault").exists() || Path::new("vault").exists();
    checks.push(GateCheck {
        name: "Vault directory exists".into(),
        passed: vault_exists,
        detail: if vault_exists {
            "ok".into()
        } else {
            "Run vault.init()".into()
        },
        blocker: true,
    });

    // cargo check must pass
    let cargo_ok = tokio::process::Command::new("cargo")
        .args(["check", "--workspace", "--quiet"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    checks.push(GateCheck {
        name: "cargo check --workspace".into(),
        passed: cargo_ok,
        detail: if cargo_ok {
            "0 errors".into()
        } else {
            "cargo check failed".into()
        },
        blocker: true,
    });

    checks
}

// ── P2 → P3: Engine complete, security active ─────────────────

async fn check_p2_to_p3() -> Vec<GateCheck> {
    let mut checks = vec![];

    // cargo clippy zero warnings
    let clippy_out = tokio::process::Command::new("cargo")
        .args(["clippy", "--workspace", "--quiet", "--", "-D", "warnings"])
        .output()
        .await
        .ok();
    let clippy_ok = clippy_out
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);
    checks.push(GateCheck {
        name: "cargo clippy — zero warnings".into(),
        passed: clippy_ok,
        detail: if clippy_ok {
            "0 warnings".into()
        } else {
            "Fix clippy warnings before P3".into()
        },
        blocker: true,
    });

    // cargo test all pass
    let test_ok = tokio::process::Command::new("cargo")
        .args(["test", "--workspace", "--quiet"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    checks.push(GateCheck {
        name: "cargo test --workspace".into(),
        passed: test_ok,
        detail: if test_ok {
            "all tests pass".into()
        } else {
            "test failures".into()
        },
        blocker: true,
    });

    // seccomp filter active on running agent
    let seccomp_active = check_seccomp_active();
    checks.push(GateCheck {
        name: "seccomp filter active on agent process".into(),
        passed: seccomp_active,
        detail: if seccomp_active {
            "Seccomp: 2".into()
        } else {
            "Start agent and verify apply_filter()".into()
        },
        blocker: true,
    });

    // cgroups configured
    let cgroup_ok = Path::new("/sys/fs/cgroup/clawos/agent").exists();
    checks.push(GateCheck {
        name: "cgroup v2 slices configured".into(),
        passed: cgroup_ok,
        detail: if cgroup_ok {
            "ok".into()
        } else {
            "Run scripts/setup-cgroups.sh".into()
        },
        blocker: true,
    });

    // Network namespace configured
    let netns_ok = check_netns_active().await;
    checks.push(GateCheck {
        name: "Network namespace 'clawos-agent' active".into(),
        passed: netns_ok,
        detail: if netns_ok {
            "ok".into()
        } else {
            "Run scripts/setup-netns.sh".into()
        },
        blocker: false, // Warn not block — can configure in P3
    });

    checks
}

// ── P3 → P4: All tools, channels, migration ──────────────────

async fn check_p3_to_p4() -> Vec<GateCheck> {
    let mut checks = vec![];
    let tools_dir = Path::new("/var/lib/clawos/tools");

    let required_tools = ["web-search", "file-read", "summarise"];
    for tool in &required_tools {
        let wasm_path = tools_dir.join(tool).join("tool.wasm");
        let present = wasm_path.exists();
        checks.push(GateCheck {
            name: format!("Tool '{tool}' WASM binary present"),
            passed: present,
            detail: if present {
                wasm_path.display().to_string()
            } else {
                format!("Build: cargo component build -p {tool}")
            },
            blocker: true,
        });
    }

    // Migration complete
    let migration_done = check_vault_entry("migration-pg-to-clawfs").await;
    checks.push(GateCheck {
        name: "PostgreSQL → ClawFS migration recorded in Vault".into(),
        passed: migration_done,
        detail: if migration_done {
            "vault entry present".into()
        } else {
            "Run migrations/pg_to_clawfs.py".into()
        },
        blocker: false,
    });

    // AppArmor enforce mode
    let aa_ok = check_apparmor_enforce().await;
    checks.push(GateCheck {
        name: "AppArmor in enforce mode".into(),
        passed: aa_ok,
        detail: if aa_ok {
            "enforce".into()
        } else {
            "Run: aa-enforce /etc/apparmor.d/clawos-agent".into()
        },
        blocker: true,
    });

    // eBPF monitor running
    let ebpf_running = tokio::process::Command::new("pgrep")
        .args(["-x", "clawos-ebpf"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    checks.push(GateCheck {
        name: "eBPF monitor daemon running".into(),
        passed: ebpf_running,
        detail: if ebpf_running {
            "ok".into()
        } else {
            "Start: clawos-ebpf-userspace &".into()
        },
        blocker: true,
    });

    checks
}

// ── P4 → Release ─────────────────────────────────────────────

async fn check_p4_to_release() -> Vec<GateCheck> {
    let mut checks = vec![];

    // ── FIX M-03: Security report verified via Vault SHA256 ──────────────────
    //
    // Previously: gate read the latest JSON from /var/lib/clawos/security/ and
    // trusted its `gate_status` field — any process that could write to that
    // directory could forge a PASS result and bypass the gate entirely.
    //
    // Now: the security report must be *frozen in the Vault* (RULE-002) before
    // the gate runs. We:
    //   1. Look up the vault record for "security-report-p4".
    //   2. Compute the SHA256 of the actual file on disk.
    //   3. Verify they match (tamper detection).
    //   4. Only then read gate_status from the verified content.
    //
    // An attacker who modifies the report file will produce a hash mismatch
    // and the gate will fail (blocker). An attacker who modifies the vault
    // record hits the Vault's own write-once protection (RULE-003).

    let sec_check = verify_vault_report(
        "security-report-p4",
        "/var/lib/clawos/security",
        "gate_status",
        "PASS",
    )
    .await;
    checks.push(GateCheck {
        name: "Security report gate status PASS (Vault-verified)".into(),
        passed: sec_check.is_ok(),
        detail: sec_check.unwrap_or_else(|e| e.to_string()),
        blocker: true,
    });

    // ── Benchmark ≥ 80% — also Vault-verified ──────────────────────────────
    let bench_check = verify_vault_report(
        "benchmark-report-p4",
        "/var/lib/clawos/calibration",
        "gate_status",
        "PASS",
    )
    .await;
    checks.push(GateCheck {
        name: "Benchmark ≥ 80% of IronClaw baseline (Vault-verified)".into(),
        passed: bench_check.is_ok(),
        detail: bench_check.unwrap_or_else(|e| e.to_string()),
        blocker: true,
    });

    // ISO ≤ 128MB
    let iso_path = Path::new("image/clawos-v0.1.0.iso");
    let iso_ok = if iso_path.exists() {
        let size_mb = iso_path
            .metadata()
            .map(|m| m.len() / 1024 / 1024)
            .unwrap_or(999);
        size_mb <= 128
    } else {
        false
    };
    checks.push(GateCheck {
        name: "ISO size ≤ 128MB".into(),
        passed: iso_ok,
        detail: if iso_ok {
            "ok".into()
        } else {
            "Build ISO: make -C buildroot-2024.11".into()
        },
        blocker: true,
    });

    // QEMU test pass
    // ❌ 現在：
    //let qemu_report = Path::new("/tmp/clawos-qemu-test-result");
    //let qemu_ok = qemu_report.exists() &&
    //    std::fs::read_to_string(qemu_report).ok()
    //        .map(|s| s.contains("PASS"))
    //        .unwrap_or(false);
    //checks.push(GateCheck {
    //    name:    "QEMU integration test PASS".into(),
    //    passed:  qemu_ok,
    //    detail:  if qemu_ok { "ok".into() } else { "Run scripts/qemu-test.sh".into() },
    //    blocker: true,
    //});

    // ✅ 修復：QEMU 測試完成後，scripts/qemu-test.sh 應將結果 freeze 進 Vault，
    //         gate 改為從 Vault 驗證：
    let qemu_check =
        verify_vault_report("qemu-test-p4", "/var/lib/clawos/qemu", "result", "PASS").await;
    checks.push(GateCheck {
        name: "QEMU integration test PASS (Vault-verified)".into(),
        passed: qemu_check.is_ok(),
        detail: qemu_check.unwrap_or_else(|e| e.to_string()),
        blocker: true,
    });
    //同時更新 scripts/qemu-test.sh，測試結束後將結果寫入 /var/lib/clawos/qemu/qemu-test-result.json
    //並呼叫 vault.freeze("qemu-test-p4")。

    // B-02 Penetration test PASS — Vault-verified
    let pentest_check = verify_vault_report(
        "pentest-report-p4",
        "/var/lib/clawos/security",
        "gate_status",
        "PASS",
    )
    .await;
    checks.push(GateCheck {
        name: "B-02 Penetration test PASS (Vault-verified)".into(),
        passed: pentest_check.is_ok(),
        detail: pentest_check.unwrap_or_else(|e| e.to_string()),
        blocker: true,
    });

    // cargo test --workspace
    let test_result = tokio::process::Command::new("cargo")
        .args(["test", "--workspace", "--quiet"])
        .env("RUST_LOG", "error") // suppress noisy output
        .output()
        .await;
    let tests_ok = test_result.map(|o| o.status.success()).unwrap_or(false);
    checks.push(GateCheck {
        name: "cargo test --workspace".into(),
        passed: tests_ok,
        detail: if tests_ok {
            "All tests pass".into()
        } else {
            "Run: cargo test --workspace".into()
        },
        blocker: true,
    });

    // git tag v0.1.0 present
    let tag_result = tokio::process::Command::new("git")
        .args(["tag", "-l", "v0.1.0"])
        .output()
        .await;
    let tagged = tag_result
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "v0.1.0")
        .unwrap_or(false);
    checks.push(GateCheck {
        name: "git tag v0.1.0 exists".into(),
        passed: tagged,
        detail: if tagged {
            "v0.1.0 tag present".into()
        } else {
            "Run: git tag -s v0.1.0 -m 'ClawOS v0.1.0'".into()
        },
        blocker: true,
    });

    // HNSW index built (recommended — non-blocker)
    let hnsw_ok = Path::new("/var/lib/clawos/clawfs.db").exists();
    checks.push(GateCheck {
        name: "HNSW index built (not linear scan)".into(),
        passed: hnsw_ok,
        detail: if hnsw_ok {
            "ClawFS DB present — index loads on startup".into()
        } else {
            "Run: cargo test -p clawfs -- hnsw (recommended)".into()
        },
        blocker: false, // recommended, not required
    });

    checks
}

// ── Helpers ───────────────────────────────────────────────────

fn check_frozen_flag(path: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| v["frozen"].as_bool() == Some(true))
        .unwrap_or(false)
}

fn check_seccomp_active() -> bool {
    // Read our own seccomp mode from /proc/self/status
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("Seccomp:")).map(|l| {
                l.split_whitespace()
                    .nth(1)
                    .unwrap_or("0")
                    .trim()
                    .to_string()
            })
        })
        .map(|v| v == "2")
        .unwrap_or(false)
}

async fn check_netns_active() -> bool {
    tokio::process::Command::new("ip")
        .args(["netns", "list"])
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("clawos-agent"))
        .unwrap_or(false)
}

async fn check_apparmor_enforce() -> bool {
    tokio::process::Command::new("aa-status")
        .output()
        .await
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("clawos-agent")
                && !s
                    .lines()
                    .skip_while(|l| !l.contains("complain"))
                    .any(|l| l.contains("clawos-agent"))
        })
        .unwrap_or(false)
}

async fn check_vault_entry(spec_id: &str) -> bool {
    let paths = [
        format!("/var/lib/clawos/vault/{spec_id}.json"),
        format!("vault/{spec_id}.json"),
    ];
    paths.iter().any(|p| Path::new(p).exists())
}

// ── FIX M-03: Vault-verified report check ────────────────────────────────────
//
// Replaces the previous `find_latest_json` + trust-the-file approach.
//
// Steps:
//   1. Locate the Vault record for `spec_id` (vault/<spec_id>.json).
//   2. Find the actual report file in `report_dir` whose name matches the
//      path recorded in the vault entry.
//   3. Compute SHA256 of the file on disk.
//   4. Compare against the hash in the vault entry (tamper detection).
//   5. Parse the verified JSON and check that `field_name` == `expected_value`.
//
// Returns Ok(detail_string) on success, Err(reason) if any step fails.

async fn verify_vault_report(
    spec_id: &str,
    report_dir: &str,
    field_name: &str,
    expected_value: &str,
) -> Result<String, String> {
    use serde_json::Value;

    // 1. Load vault record
    let vault_paths = [
        format!("/var/lib/clawos/vault/{spec_id}.json"),
        format!("vault/{spec_id}.json"),
    ];
    let vault_json = vault_paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .ok_or_else(|| {
            format!(
                "Vault record '{spec_id}' not found — run scripts/security-report.sh \
             then freeze with vault.freeze()"
            )
        })?;

    let vault_entry: Value = serde_json::from_str(&vault_json)
        .map_err(|e| format!("Vault record '{spec_id}' is malformed JSON: {e}"))?;

    let expected_sha = vault_entry["sha256"]
        .as_str()
        .ok_or_else(|| format!("Vault record '{spec_id}' missing sha256 field"))?;
    let recorded_path = vault_entry["path"]
        .as_str()
        .ok_or_else(|| format!("Vault record '{spec_id}' missing path field"))?;

    // 2. Resolve report file — must be under report_dir (path traversal guard)
    let report_path = std::path::PathBuf::from(recorded_path);

    // FIX SEC-4: canonicalize() returns Err when the file does not yet exist,
    // and the previous fallback `unwrap_or_else(|_| PathBuf::from(recorded_path))`
    // returned the raw unresolved path — a symlink created before the file exists
    // would not be caught by the subsequent starts_with check.
    // Corrected: require the file to exist before canonicalizing so that symlinks
    // are always resolved and the directory prefix check is meaningful.
    if !report_path.exists() {
        return Err(format!(
            "Report file '{}' recorded in Vault does not exist on disk",
            recorded_path
        ));
    }

    let canonical = report_path
        .canonicalize()
        .map_err(|e| format!("Cannot canonicalize report path '{}': {e}", recorded_path))?;

    let dir_canonical = std::path::Path::new(report_dir)
        .canonicalize()
        .map_err(|e| format!("Cannot canonicalize report_dir '{}': {e}", report_dir))?;

    if !canonical.starts_with(&dir_canonical) {
        return Err(format!(
            "Vault record '{spec_id}' points to '{}' which is outside \
             expected directory '{}' — possible tampering",
            recorded_path, report_dir
        ));
    }

    // 3. Compute SHA256 of the actual file
    let file_data = std::fs::read(&report_path)
        .map_err(|e| format!("Cannot read report file '{}': {e}", recorded_path))?;
    let actual_sha = sha256_hex(&file_data);

    // 4. Verify hash matches vault record (tamper detection)
    if actual_sha != expected_sha {
        return Err(format!(
            "SHA256 MISMATCH for '{spec_id}': vault={} disk={} — \
             report file has been modified after freezing (RULE-002 violation)",
            &expected_sha[..16],
            &actual_sha[..16]
        ));
    }

    // 5. Parse the now-verified content and check the expected field
    let report: Value = serde_json::from_slice(&file_data)
        .map_err(|e| format!("Verified report '{recorded_path}' is not valid JSON: {e}"))?;

    let actual_value = report[field_name].as_str().unwrap_or("<missing>");
    if actual_value != expected_value {
        return Err(format!(
            "Report '{spec_id}': {field_name}={actual_value:?} (expected {expected_value:?})"
        ));
    }

    Ok(format!(
        "{field_name}={expected_value} ✓ (SHA256 verified: {}…)",
        &actual_sha[..16]
    ))
}

/// SHA256 of a byte slice, hex-encoded.  Mirrors vault.rs sha256_hex().
fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut hex = String::with_capacity(64);
    for b in digest.as_ref() {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}

// `find_latest_json` is retained for P1–P3 gates that do not yet use Vault
// verification, but is no longer used in the P4→Release gate (FIX M-03).
fn find_latest_json(dir: &Path) -> Option<std::path::PathBuf> {
    if !dir.exists() {
        return None;
    }
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .max_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
        .map(|e| e.path())
}
