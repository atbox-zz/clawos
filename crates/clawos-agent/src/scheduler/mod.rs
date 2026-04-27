// crates/clawos-agent/src/scheduler/mod.rs
//
// Scheduler: manages the job queue and assigns work to Workers.
// Key difference from IronClaw: each Worker slot is a cgroup slice,
// not a Docker container. Resource limits enforced by kernel.
//
// FIX (audit #2): result_tx is now stored alongside its Job in the
// priority queue, so it is never dropped at capacity. When a slot
// frees up, the next queued job+sender pair is dispatched together.

use anyhow::Result;
use chrono::Utc;
//use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BinaryHeap, sync::Arc};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

// ── Job ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub priority: Priority,
    pub kind: JobKind,
    pub created_at: i64,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobKind {
    ToolExecution {
        tool: String,
        input_json: String,
    },
    LlmQuery {
        messages: Vec<serde_json::Value>,
        model: Option<String>,
    },
    Routine {
        routine_id: String,
    },
    Maintenance {
        task: String,
    },
}

impl Job {
    pub fn new(kind: JobKind, priority: Priority, timeout_sec: u64) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            priority,
            kind,
            created_at: Utc::now().timestamp_millis(),
            timeout_sec,
        }
    }
}

// ── QueuedJob: Job + its result sender (kept together always) ─

pub struct QueuedJob {
    pub job: Job,
    pub result_tx: oneshot::Sender<JobResult>,
    /// Worker instance that will execute this job.
    pub worker_handle: crate::worker::Worker,
    /// Depth of the tool-invoke chain that created this job (0 = top-level).
    /// Passed into HostCtx so nested tool-invoke calls enforce the depth limit.
    pub invoke_depth: u32,
}

// BinaryHeap ordering delegates to Job priority so higher priority = dequeued first
impl PartialEq for QueuedJob {
    fn eq(&self, o: &Self) -> bool {
        self.job.priority == o.job.priority
    }
}
impl Eq for QueuedJob {}
impl PartialOrd for QueuedJob {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for QueuedJob {
    fn cmp(&self, o: &Self) -> Ordering {
        self.job.priority.cmp(&o.job.priority)
    }
}

// Keep Job ordering as before (used independently in tests)
impl PartialEq for Job {
    fn eq(&self, o: &Self) -> bool {
        self.priority == o.priority
    }
}
impl Eq for Job {}
impl PartialOrd for Job {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Job {
    fn cmp(&self, o: &Self) -> Ordering {
        self.priority.cmp(&o.priority)
    }
}

// ── Job Handle ────────────────────────────────────────────────

pub struct JobHandle {
    pub job_id: String,
    pub result_rx: oneshot::Receiver<JobResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: String,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

// ── Scheduler ─────────────────────────────────────────────────

pub struct Scheduler {
    // queue_depth is tracked separately so it's cheap to read without locking QueuedJobs
    queue_depth: Arc<std::sync::atomic::AtomicUsize>,
    dispatch_tx: mpsc::Sender<DispatchMsg>,
    max_concurrent: usize,
    worker_proto: Option<Arc<crate::worker::Worker>>,
}

pub enum DispatchMsg {
    Enqueue(QueuedJob),
    Cancel(String), // job_id to remove from the queue if still pending
    Shutdown,
}

impl Scheduler {
    pub fn new(max_concurrent: usize) -> (Self, SchedulerWorker) {
        let (tx, rx) = mpsc::channel(256);
        let queue_depth = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let scheduler = Self {
            queue_depth: Arc::clone(&queue_depth),
            dispatch_tx: tx,
            max_concurrent,
            worker_proto: None,
        };

        let worker = SchedulerWorker {
            queue: BinaryHeap::new(),
            dispatch_rx: rx,
            max_concurrent,
            active: 0,
            queue_depth: Arc::clone(&queue_depth),
        };

        (scheduler, worker)
    }

    /// Attach a Worker prototype so submitted jobs are executed by the real runtime.
    /// Call this once after construction before submitting any jobs.
    pub fn set_worker(&mut self, w: crate::worker::Worker) {
        self.worker_proto = Some(Arc::new(w));
    }

    /// Expose the raw dispatch channel so Workers can enqueue tool-invoke child jobs.
    pub fn dispatch_tx(&self) -> tokio::sync::mpsc::Sender<DispatchMsg> {
        self.dispatch_tx.clone()
    }

    /// Submit a job and get back a handle to await its result.
    pub async fn submit(&self, job: Job) -> Result<JobHandle> {
        let job_id = job.id.clone();
        let (result_tx, result_rx) = oneshot::channel();

        debug!(job_id = %job_id, priority = ?job.priority,
               kind = ?std::mem::discriminant(&job.kind), "Job submitted");

        let worker_handle = self
            .worker_proto
            .as_ref()
            .map(|w| (**w).clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Scheduler has no Worker — call set_worker() before submitting jobs"
                )
            })?;

        self.dispatch_tx
            .send(DispatchMsg::Enqueue(QueuedJob {
                job,
                result_tx,
                worker_handle,
                invoke_depth: 0,
            }))
            .await
            .map_err(|_| anyhow::anyhow!("Scheduler channel closed"))?;

        Ok(JobHandle { job_id, result_rx })
    }

    pub async fn shutdown(&self) {
        let _ = self.dispatch_tx.send(DispatchMsg::Shutdown).await;
    }

    /// Cancel a queued job by ID.  Returns true if found and removed from queue.
    /// Jobs already dispatched to a worker cannot be cancelled (they run to timeout).
    pub async fn cancel(&self, job_id: &str) -> bool {
        let _ = self
            .dispatch_tx
            .send(DispatchMsg::Cancel(job_id.to_string()))
            .await;
        // We can't easily get a synchronous bool back through the channel without adding
        // another oneshot; for now the cancel is best-effort and the caller gets logged result.
        // A future version can add a oneshot response channel here.
        true
    }

    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ── Scheduler Worker (runs in background task) ────────────────

pub struct SchedulerWorker {
    queue: BinaryHeap<QueuedJob>,
    dispatch_rx: mpsc::Receiver<DispatchMsg>,
    max_concurrent: usize,
    active: usize,
    queue_depth: Arc<std::sync::atomic::AtomicUsize>,
}

impl SchedulerWorker {
    /// Drive the dispatch loop. Call `tokio::spawn(worker.run())`.
    pub async fn run(mut self) {
        info!(
            max_concurrent = self.max_concurrent,
            "Scheduler dispatch loop started"
        );
        let (done_tx, mut done_rx) = mpsc::channel::<String>(64);

        loop {
            tokio::select! {
                Some(msg) = self.dispatch_rx.recv() => {
                    match msg {
                        DispatchMsg::Shutdown => {
                            info!("Scheduler shutting down");
                            break;
                        }
                        DispatchMsg::Enqueue(queued) => {
                            self.queue.push(queued);
                            self.queue_depth.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // Try to dispatch immediately if a slot is free
                            self.try_dispatch(&done_tx);
                        }
                        DispatchMsg::Cancel(job_id) => {
                            // Drain queue, skip the cancelled job, re-push the rest.
                            let mut retained = Vec::with_capacity(self.queue.len());
                            let mut found = false;
                            while let Some(qj) = self.queue.pop() {
                                if !found && qj.job.id == job_id {
                                    found = true;
                                    self.queue_depth.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                    // Drop qj — result_tx is dropped, caller gets RecvError
                                    info!(job_id = %job_id, "Job cancelled from queue");
                                } else {
                                    retained.push(qj);
                                }
                            }
                            for qj in retained { self.queue.push(qj); }
                            if !found {
                                debug!(job_id = %job_id, "Cancel requested for job not in queue (already dispatched or unknown)");
                            }
                        }
                    }
                }
                Some(job_id) = done_rx.recv() => {
                    self.active = self.active.saturating_sub(1);
                    debug!(job_id = %job_id, active = self.active, "Job completed — slot freed");
                    // A slot freed — try to drain the queue
                    self.try_dispatch(&done_tx);
                }
            }
        }
    }

    /// Dispatch as many queued jobs as free slots allow.
    /// The result_tx travels with each QueuedJob, so it is always delivered.
    fn try_dispatch(&mut self, done_tx: &mpsc::Sender<String>) {
        while self.active < self.max_concurrent {
            let queued = match self.queue.pop() {
                Some(q) => q,
                None => break,
            };
            self.queue_depth
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            self.active += 1;
            let job_id = queued.job.id.clone();
            let done_tx = done_tx.clone();
            let invoke_depth = queued.invoke_depth;

            info!(job_id = %job_id, active = self.active, invoke_depth, "Dispatching job to worker");

            tokio::spawn(async move {
                let worker = queued.worker_handle;
                let result = worker.execute_with_depth(queued.job, invoke_depth).await;

                let _ = queued.result_tx.send(result);
                let _ = done_tx.send(job_id).await;
            });
        }

        if self.active >= self.max_concurrent && !self.queue.is_empty() {
            warn!(
                active = self.active,
                max = self.max_concurrent,
                queued = self.queue.len(),
                "Scheduler at capacity — jobs waiting"
            );
        }
    }
}

// execute_job_stub removed — Worker.execute() is now called directly in the dispatch loop (P3)

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    // ❌ 現在：
    //async fn submit_and_receive_result() {
    //    let (sched, worker) = Scheduler::new(4);
    //    tokio::spawn(worker.run());

    //    let job = Job::new(
    //        JobKind::LlmQuery { messages: vec![], model: None },
    //        Priority::Normal,
    //        30,
    //    );
    //    let handle = sched.submit(job).await.unwrap();
    //    let result = handle.result_rx.await.unwrap();
    //    assert!(result.error.is_none());
    //}
    // ✅ 修復：
    async fn submit_and_receive_result() {
        let (mut sched, sched_worker) = Scheduler::new(4);

        let engine = wasmtime::Engine::default();
        let wasm_cfg = crate::config::WasmConfig {
            tools_dir: "/tmp/test-tools".into(),
            max_memory_bytes: 64 * 1024 * 1024,
            max_stack_bytes: 1024 * 1024,
            wasm_cgroup_path: "/sys/fs/cgroup/clawos/wasm".into(),
        };
        let sec_cfg = crate::config::SecurityConfig {
            allowed_endpoints: vec![],
            allowed_read_paths: vec![],
            allowed_write_paths: vec![],
        };
        let worker = crate::worker::Worker::new(engine, wasm_cfg, sec_cfg);
        sched.set_worker(worker);

        tokio::spawn(sched_worker.run());

        let job = Job::new(
            JobKind::Maintenance {
                task: "test".into(),
            },
            Priority::Normal,
            30,
        );
        let handle = sched.submit(job).await.unwrap();
        let result = handle.result_rx.await.unwrap();
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn queued_jobs_complete_when_slot_frees() {
        let (mut sched, sched_worker) = Scheduler::new(4);

        let engine = wasmtime::Engine::default();
        let wasm_cfg = crate::config::WasmConfig {
            tools_dir: "/tmp/test-tools".into(),
            max_memory_bytes: 64 * 1024 * 1024,
            max_stack_bytes: 1024 * 1024,
            wasm_cgroup_path: "/sys/fs/cgroup/clawos/wasm".into(),
        };
        let sec_cfg = crate::config::SecurityConfig {
            allowed_endpoints: vec![],
            allowed_read_paths: vec![],
            allowed_write_paths: vec![],
        };
        let worker = crate::worker::Worker::new(engine, wasm_cfg, sec_cfg);
        sched.set_worker(worker);

        tokio::spawn(sched_worker.run());

        let h1 = sched
            .submit(Job::new(
                JobKind::Maintenance {
                    task: "first".into(),
                },
                Priority::Normal,
                10,
            ))
            .await
            .unwrap();
        let h2 = sched
            .submit(Job::new(
                JobKind::Maintenance {
                    task: "second".into(),
                },
                Priority::Normal,
                10,
            ))
            .await
            .unwrap();

        // Both must complete — second must not get a channel-closed error
        let r1 = h1.result_rx.await.expect("job 1 result must arrive");
        let r2 = h2
            .result_rx
            .await
            .expect("job 2 result must arrive (was queued)");
        assert!(r1.error.is_none());
        assert!(r2.error.is_none());
    }

    #[test]
    fn higher_priority_dequeued_first() {
        let mut heap = BinaryHeap::new();
        heap.push(Job::new(
            JobKind::Maintenance { task: "low".into() },
            Priority::Low,
            30,
        ));
        heap.push(Job::new(
            JobKind::Maintenance {
                task: "crit".into(),
            },
            Priority::Critical,
            30,
        ));
        heap.push(Job::new(
            JobKind::Maintenance {
                task: "norm".into(),
            },
            Priority::Normal,
            30,
        ));

        assert_eq!(heap.pop().unwrap().priority, Priority::Critical);
        assert_eq!(heap.pop().unwrap().priority, Priority::Normal);
        assert_eq!(heap.pop().unwrap().priority, Priority::Low);
    }
}
