// seccomp Whitelist Pruning (P4.1)
//
// This module implements strace analysis and syscall profiling

use crate::error::{SecurityError, SecurityResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallStats {
    pub syscall_name: String,
    pub call_count: u64,
    pub processes_using: u32,
    pub avg_duration_ns: u64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StraceAnalysis {
    pub process_name: String,
    pub duration_secs: u64,
    pub total_syscalls: u64,
    pub syscall_stats: Vec<SyscallStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PruningAction {
    Keep,
    Remove,
    AddConditional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningRecommendation {
    pub syscall: String,
    pub action: PruningAction,
    pub reason: String,
    pub confidence: f64,
}

pub struct SeccompPruner;

impl SeccompPruner {
    pub fn analyze_strace_output(strace_output: &str) -> SecurityResult<StraceAnalysis> {
        let mut syscall_stats: HashMap<String, (u64, u32)> = HashMap::new();
        let mut total_syscalls: u64 = 0;
        
        let line_re = Regex::new(r"^\s*(\d+)\s+(\w+)\(").unwrap();
        
        for line in strace_output.lines() {
            if let Some(caps) = line_re.captures(line) {
                let count: u64 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
                let syscall = caps.get(2).unwrap().as_str().to_string();
                
                let entry = syscall_stats.entry(syscall.clone()).or_insert((0, 0));
                entry.0 += count;
                entry.1 += 1;
                total_syscalls += count;
            }
        }
        
        let stats: Vec<SyscallStats> = syscall_stats
            .into_iter()
            .map(|(name, (count, processes))| SyscallStats {
                syscall_name: name,
                call_count: count,
                processes_using: processes,
                avg_duration_ns: 0,
                error_rate: 0.0,
            })
            .collect();
        
        Ok(StraceAnalysis {
            process_name: "unknown".to_string(),
            duration_secs: 0,
            total_syscalls,
            syscall_stats: stats,
        })
    }
    
    pub fn generate_pruning_recommendations(
        analysis: &StraceAnalysis,
        current_whitelist: &HashSet<String>,
    ) -> Vec<PruningRecommendation> {
        let mut recommendations = vec![];
        
        const RARE_THRESHOLD: u64 = 10;
        
        for stat in &analysis.syscall_stats {
            if stat.call_count < RARE_THRESHOLD {
                recommendations.push(PruningRecommendation {
                    syscall: stat.syscall_name.clone(),
                    action: PruningAction::Remove,
                    reason: format!("Only {} calls, extremely rare", stat.call_count),
                    confidence: 0.9,
                });
            }
        }
        
        recommendations
    }
}
