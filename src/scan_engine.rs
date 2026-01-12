use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::io::AsyncWriteExt;
use std::io::Write;
use crate::config::Config;
use crate::files::FilesHandler;
use crate::net_tools::NetTools;
use crate::brute_engine::BruteEngine;
use crate::rfb::RFBProtocol; 

pub struct ScanEngine {
    config: Arc<Config>,
    files: Arc<FilesHandler>,
    net_tools: Arc<NetTools>,
}

impl ScanEngine {
    pub fn new(config: Arc<Config>, files: Arc<FilesHandler>, net_tools: Arc<NetTools>) -> Self {
        Self {
            config,
            files,
            net_tools,
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let range = self.net_tools.convert_range(&self.config.scan_range)
            .ok_or("Invalid scan range")?;
        
        let (start_ip, end_ip) = range;
        let total = end_ip.saturating_sub(start_ip) as usize;
        
        // Limit concurrency and avoid spawning all tasks at once
        let semaphore = Arc::new(Semaphore::new(self.config.scan_threads.min(2000)));
        let found = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let current = Arc::new(std::sync::atomic::AtomicU64::new(0));
        
        // Async writer for ips to avoid blocking the runtime
        let ips_path = self.files.get_ips_path();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1000);
        let writer_handle = tokio::spawn(async move {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&ips_path)
                .await
                .expect("Failed to open ips file");
            while let Some(line) = rx.recv().await {
                if let Err(e) = file.write_all(line.as_bytes()).await {
                    eprintln!("Failed to write ip: {}", e);
                }
                let _ = file.write_all(b"\n").await;
                let _ = file.flush().await;
            }
        });
        
        // Output task (reads atomics)
        let current_clone = current.clone();
        let found_clone = found.clone();
        let output_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let curr = current_clone.load(std::sync::atomic::Ordering::Relaxed);
                let fnd = found_clone.load(std::sync::atomic::Ordering::Relaxed);
                if curr as usize >= total {
                    break;
                }
                let msg = format!(" Current [{}/{}] Found: {}", curr, total, fnd);
                print!("\r{:<80}", msg);
                std::io::stdout().flush().ok();
            }
        });
        
        // === JOB-BASED SCANNER (bounded queue + retry + watchdog) ===
        use tokio::sync::mpsc;
        use dashmap::DashMap;
        use tokio_util::time::DelayQueue;
        use rand::Rng;
        use tokio::time::Instant as TokioInstant;
        use tokio::time::sleep;

        #[derive(Clone, Debug)]
        struct Job { id: u64, ip: String, port: u16, retries: u8 }

        let input_queue_size = 10000usize; // bounded input queue
        let max_retries = 5u8;
        let base_backoff_ms = 100u64;
        let max_backoff_ms = 60_000u64;
        let in_flight_timeout_ms = 30_000u64;

        let total_jobs = (end_ip.saturating_sub(start_ip) + 1) as u64;
        let finalized = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Input queue (bounded, backpressure)
        let (job_tx, mut job_rx) = mpsc::channel::<Job>(input_queue_size);

        // In-flight tracking
        let in_flight = Arc::new(DashMap::<u64, (Job, TokioInstant)>::new());

        // Retry scheduler channel (producers send (job, delay) here)
        let (retry_schedule_tx, mut retry_schedule_rx) = tokio::sync::mpsc::channel::<(Job, Duration)>(10000);

        // Wrap receiver in a mutex so workers can await recv (exclusive receiver)
        let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));

        // Spawn worker pool
        let worker_count = std::cmp::max(4, num_cpus::get() * 4);
        let mut worker_handles = Vec::new();
        for _ in 0..worker_count {
            let job_rx = job_rx.clone();
            let sem = semaphore.clone();
            let tx_writer = tx.clone();
            let retry_tx = retry_schedule_tx.clone();
            let in_flight = in_flight.clone();
            let found = found.clone();
            let finalized = finalized.clone();
            let net_tools = self.net_tools.clone();
            let cfg = self.config.clone();

            let h = tokio::spawn(async move {
                loop {
                    // receive next job (exclusive access to receiver)
                    let maybe_job = { let mut rx_lock = job_rx.lock().await; rx_lock.recv().await };
                    let mut job = match maybe_job {
                        Some(j) => j,
                        None => break, // channel closed
                    };

                    // mark in-flight
                    in_flight.insert(job.id, (job.clone(), TokioInstant::now()));

                    // acquire permit
                    let permit = sem.clone().acquire_owned().await.unwrap();

                    // attempt
                    let ip = job.ip.clone();
                    let mut rfb = RFBProtocol::new(&ip, "", job.port, cfg.scan_timeout);
                    match rfb.connect().await {
                        Ok(_) => {
                            // success
                            let _ = tx_writer.send(format!("{}:{}", job.ip, job.port)).await;
                            found.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // finalize
                            in_flight.remove(&job.id);
                            finalized.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_e) => {
                            // retry or finalize
                            if job.retries < max_retries {
                                job.retries += 1;
                                // jittered backoff (rng scoped)
                                let backoff = std::cmp::min(max_backoff_ms, base_backoff_ms.saturating_mul(1u64 << (job.retries as u32)));
                                let delay = { let mut rng = rand::thread_rng(); Duration::from_millis(rng.gen_range(0..=backoff)) };
                                let _ = retry_tx.send((job.clone(), delay)).await;
                                in_flight.remove(&job.id);
                            } else {
                                // drop/finalize
                                in_flight.remove(&job.id);
                                finalized.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }

                    drop(permit);
                }
            });

            worker_handles.push(h);
        }

        // Producer: enqueue initial jobs (backpressures if channel full)
        let mut submitted = 0u64;
        for ip_int in start_ip..=end_ip {
            let job = Job { id: ip_int as u64, ip: self.net_tools.int2ip(ip_int), port: self.config.scan_port, retries: 0 };
            job_tx.send(job).await.expect("input queue closed");
            submitted += 1;
        }

        let job_tx_clone = job_tx.clone();
        let retry_handle = tokio::spawn(async move {
            use futures::StreamExt;
            let mut dq = DelayQueue::<Job>::new();
            loop {
                tokio::select! {
                    biased;
                    Some((job, delay)) = retry_schedule_rx.recv() => {
                        dq.insert(job, delay);
                    }
                    maybe = dq.next() => {
                        if let Some(expired) = maybe {
                            let job = expired.into_inner();
                            if let Err(_) = job_tx_clone.send(job).await { break; }
                        }
                    }
                }
            }
        });

        // Watchdog: detect stale in-flight and requeue
        let retry_tx_clone = retry_schedule_tx.clone();
        let in_flight_clone = in_flight.clone();
        let finalized_wd = finalized.clone();
        let wd_handle = tokio::spawn(async move {
            loop {
                let now = TokioInstant::now();
                let mut stale = Vec::new();
                for kv in in_flight_clone.iter() {
                    let (job, when) = kv.value();
                    if now.duration_since(*when).as_millis() as u64 > in_flight_timeout_ms {
                        stale.push(job.clone());
                    }
                }
                for job in stale {
                    if job.retries < max_retries {
                        let mut j = job.clone();
                        j.retries += 1;
                        // jitter (rng scoped)
                        let backoff = std::cmp::min(max_backoff_ms, base_backoff_ms.saturating_mul(1u64 << (j.retries as u32)));
                        let delay = { let mut rng = rand::thread_rng(); Duration::from_millis(rng.gen_range(0..=backoff)) };
                        let _ = retry_tx_clone.send((j, delay)).await;
                        // remove stale marker
                        in_flight.remove(&job.id);
                    } else {
                        // finalize as dropped
                        in_flight.remove(&job.id);
                        finalized_wd.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                sleep(Duration::from_millis(1000)).await;
            }
        });

        // Wait until all jobs reach final state
        loop {
            let fin = finalized.load(std::sync::atomic::Ordering::Relaxed);
            if fin >= total_jobs as u64 { break; }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Shutdown: close channels and wait for tasks
        drop(job_tx);
        retry_handle.abort();
        wd_handle.abort();

        for h in worker_handles { h.await.ok(); }

        // Close writer and wait for it to finish
        drop(tx);
        writer_handle.await.ok();
        output_handle.abort();

        println!("\n\nDONE! Check \"output/ips.txt\" or type \"show ips\"!\n");
        
        // Auto brute if enabled
        if self.config.auto_brute {
            let brute_engine = BruteEngine::new(
                self.config.clone(),
                self.files.clone(),
                self.net_tools.clone(),
            );
            brute_engine.start().await?;
        }
        
        Ok(())
    }
}

