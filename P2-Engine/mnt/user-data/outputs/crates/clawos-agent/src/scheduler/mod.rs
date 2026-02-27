// crates/clawos-agent/src/scheduler/mod.rs
//
// Scheduler: manages the job queue and assigns work to Workers.
// Key difference from IronClaw: each Worker slot is a cgroup slice,
// not a Docker container. Resource limits enforced by kernel.

use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::BinaryHeap, cmp::Ordering, sync::Arc};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn, debug};
use uuid::Uuid;
use chrono::Utc;

// ── Job ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id:          String,
    pub priority:    Priority,
    pub kind:        JobKind,
    pub created_at:  i64,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low      = 0,
    Normal   = 1,
    High     = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobKind {
    ToolExecution { tool: String, input_json: String },
    LlmQuery      { messages: Vec<serde_json::Value>, model: Option<String> },
    Routine       { routine_id: String },
    Maintenance   { task: String },
}

impl Job {
    pub fn new(kind: JobKind, priority: Priority, timeout_sec: u64) -> Self {
        Self {
            id:         Uuid::new_v4().to_string(),
            priority,
            kind,
            created_at: Utc::now().timestamp_millis(),
            timeout_sec,
        }
    }
}

// Binary heap ordering: higher priority = dequeued first
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool { self.priority == other.priority }
}
impl Eq for Job {}
impl PartialOrd for Job {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for Job {
    fn cmp(&self, other: &Self) -> Ordering { self.priority.cmp(&other.priority) }
}

// ── Job Handle ────────────────────────────────────────────────

pub struct JobHandle {
    pub job_id:   String,
    pub result_rx: oneshot::Receiver<JobResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id:    String,
    pub output:    serde_json::Value,
    pub error:     Option<String>,
    pub duration_ms: u64,
}

// ── Scheduler ─────────────────────────────────────────────────

pub struct Scheduler {
    queue:          Arc<Mutex<BinaryHeap<Job>>>,
    dispatch_tx:    mpsc::Sender<DispatchMsg>,
    max_concurrent: usize,
}

enum DispatchMsg {
    Enqueue(Job, oneshot::Sender<JobResult>),
    Shutdown,
}

impl Scheduler {
    pub fn new(max_concurrent: usize) -> (Self, SchedulerWorker) {
        let queue    = Arc::new(Mutex::new(BinaryHeap::new()));
        let (tx, rx) = mpsc::channel(256);

        let scheduler = Self {
            queue:          Arc::clone(&queue),
            dispatch_tx:    tx,
            max_concurrent,
        };

        let worker = SchedulerWorker {
            queue:          Arc::clone(&queue),
            dispatch_rx:    rx,
            max_concurrent,
            active:         0,
        };

        (scheduler, worker)
    }

    /// Submit a job and get back a handle to await its result.
    pub async fn submit(&self, job: Job) -> Result<JobHandle> {
        let job_id = job.id.clone();
        let (result_tx, result_rx) = oneshot::channel();

        debug!(job_id = %job_id, priority = ?job.priority, kind = ?std::mem::discriminant(&job.kind), "Job submitted");

        self.dispatch_tx.send(DispatchMsg::Enqueue(job, result_tx)).await
            .map_err(|_| anyhow::anyhow!("Scheduler channel closed"))?;

        Ok(JobHandle { job_id, result_rx })
    }

    pub async fn shutdown(&self) {
        let _ = self.dispatch_tx.send(DispatchMsg::Shutdown).await;
    }

    pub fn queue_depth(&self) -> usize {
        self.queue.lock().len()
    }
}

// ── Scheduler Worker (runs in background task) ────────────────

pub struct SchedulerWorker {
    queue:          Arc<Mutex<BinaryHeap<Job>>>,
    dispatch_rx:    mpsc::Receiver<DispatchMsg>,
    max_concurrent: usize,
    active:         usize,
}

impl SchedulerWorker {
    /// Drive the dispatch loop. Call `tokio::spawn(worker.run())`.
    pub async fn run(mut self) {
        info!(max_concurrent = self.max_concurrent, "Scheduler dispatch loop started");
        let (done_tx, mut done_rx) = mpsc::channel::<String>(64);

        loop {
            tokio::select! {
                Some(msg) = self.dispatch_rx.recv() => {
                    match msg {
                        DispatchMsg::Shutdown => {
                            info!("Scheduler shutting down");
                            break;
                        }
                        DispatchMsg::Enqueue(job, result_tx) => {
                            self.queue.lock().push(job);
                            // check if we can dispatch immediately
                            self.try_dispatch(&done_tx, result_tx).await;
                        }
                    }
                }
                Some(job_id) = done_rx.recv() => {
                    self.active = self.active.saturating_sub(1);
                    debug!(job_id = %job_id, active = self.active, "Job completed slot freed");
                }
            }
        }
    }

    async fn try_dispatch(
        &mut self,
        done_tx: &mpsc::Sender<String>,
        result_tx: oneshot::Sender<JobResult>,
    ) {
        if self.active >= self.max_concurrent {
            warn!(active = self.active, max = self.max_concurrent, "Scheduler at capacity — job queued");
            return;
        }

        let job = match self.queue.lock().pop() {
            Some(j) => j,
            None    => return,
        };

        self.active += 1;
        let job_id   = job.id.clone();
        let done_tx  = done_tx.clone();

        info!(job_id = %job_id, active = self.active, "Dispatching job to worker");

        tokio::spawn(async move {
            let start = std::time::Instant::now();

            // TODO P2: spawn actual cgroup-isolated worker here
            // For now: stub that simulates work
            let output = execute_job_stub(&job).await;

            let result = JobResult {
                job_id:      job_id.clone(),
                output,
                error:       None,
                duration_ms: start.elapsed().as_millis() as u64,
            };

            let _ = result_tx.send(result);
            let _ = done_tx.send(job_id).await;
        });
    }
}

// Stub — replaced in P2 by real cgroup worker
async fn execute_job_stub(job: &Job) -> serde_json::Value {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    serde_json::json!({
        "status":  "stub_complete",
        "job_id":  job.id,
        "message": "Worker stub — real execution in P2 D-03"
    })
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn submit_and_receive_result() {
        let (sched, worker) = Scheduler::new(4);
        tokio::spawn(worker.run());

        let job = Job::new(
            JobKind::LlmQuery { messages: vec![], model: None },
            Priority::Normal,
            30,
        );
        let handle = sched.submit(job).await.unwrap();
        let result = handle.result_rx.await.unwrap();
        assert!(result.error.is_none());
    }

    #[test]
    fn higher_priority_dequeued_first() {
        let mut heap = BinaryHeap::new();
        heap.push(Job::new(JobKind::Maintenance { task: "low".into() },  Priority::Low,      30));
        heap.push(Job::new(JobKind::Maintenance { task: "crit".into() }, Priority::Critical, 30));
        heap.push(Job::new(JobKind::Maintenance { task: "norm".into() }, Priority::Normal,   30));

        assert_eq!(heap.pop().unwrap().priority, Priority::Critical);
        assert_eq!(heap.pop().unwrap().priority, Priority::Normal);
        assert_eq!(heap.pop().unwrap().priority, Priority::Low);
    }
}
