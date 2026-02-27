// crates/clawos-agent/src/agent/memory.rs
//
// In-process conversation memory (short-term).
// Long-term memory lives in ClawFS vector store.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const DEFAULT_WINDOW: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Turn {
    pub user:      String,
    pub assistant: String,
}

pub struct Memory {
    window:   usize,
    turns:    VecDeque<Turn>,
}

impl Memory {
    pub fn new() -> Self {
        Self { window: DEFAULT_WINDOW, turns: VecDeque::new() }
    }

    pub fn with_window(window: usize) -> Self {
        Self { window, turns: VecDeque::new() }
    }

    pub fn push(&mut self, turn: Turn) {
        if self.turns.len() >= self.window {
            self.turns.pop_front();
        }
        self.turns.push_back(turn);
    }

    pub fn recent(&self, n: usize) -> Vec<Turn> {
        self.turns.iter().rev().take(n).cloned().collect::<Vec<_>>()
            .into_iter().rev().collect()
    }

    pub fn len(&self) -> usize { self.turns.len() }
    pub fn is_empty(&self) -> bool { self.turns.is_empty() }

    pub fn clear(&mut self) { self.turns.clear(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_evicts_oldest() {
        let mut m = Memory::with_window(3);
        for i in 0..5u32 {
            m.push(Turn { user: i.to_string(), assistant: "ok".into() });
        }
        assert_eq!(m.len(), 3);
        let recent = m.recent(3);
        assert_eq!(recent[0].user, "2"); // oldest retained
        assert_eq!(recent[2].user, "4"); // newest
    }

    #[test]
    fn recent_returns_in_chronological_order() {
        let mut m = Memory::new();
        m.push(Turn { user: "a".into(), assistant: "1".into() });
        m.push(Turn { user: "b".into(), assistant: "2".into() });
        m.push(Turn { user: "c".into(), assistant: "3".into() });
        let r = m.recent(2);
        assert_eq!(r[0].user, "b");
        assert_eq!(r[1].user, "c");
    }
}
