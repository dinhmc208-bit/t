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
        
        // Scan tasks
        let mut handles = Vec::new();
        
        for ip_int in start_ip..=end_ip {
            let semaphore_clone = semaphore.clone();
            let found_clone = found.clone();
            let current_clone = current.clone();
            let net_tools_clone = self.net_tools.clone();
            let config_clone = self.config.clone();
            
            // Acquire an owned permit before spawning so we don't create too many tasks
            let permit = semaphore_clone.acquire_owned().await.unwrap();
            let tx_clone = tx.clone();
            let handle = tokio::spawn(async move {
                let ip_str = net_tools_clone.int2ip(ip_int);
                // Perform RFB protocol check (not just TCP connect)
                let mut rfb = RFBProtocol::new(&ip_str, "", config_clone.scan_port, config_clone.scan_timeout);
                match rfb.connect().await {
                    Ok(_) => {
                        // RFB handshake successful, send to writer
                        let _ = tx_clone.send(format!("{}:{}", ip_str, config_clone.scan_port)).await;
                        found_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(_e) => {
                        // Not a VNC/RFB server or handshake failed
                    }
                }

                current_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                drop(permit);
            });
            
            handles.push(handle);
        }
        
        // Wait for all scans to complete
        for handle in handles {
            handle.await.ok();
        }

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

