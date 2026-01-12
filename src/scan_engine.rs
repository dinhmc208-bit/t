use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::sync::Semaphore;
use crate::config::Config;
use crate::files::FilesHandler;
use crate::net_tools::NetTools;
use crate::brute_engine::BruteEngine;
use std::fs::OpenOptions;
use std::io::Write;

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
        
        let semaphore = Arc::new(Semaphore::new(self.config.scan_threads.min(20000)));
        let found = Arc::new(Mutex::new(0u64));
        let current = Arc::new(Mutex::new(0u64));
        
        let ips_path = self.files.get_ips_path();
        let file = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&ips_path)?,
        ));
        
        // Output task
        let current_clone = current.clone();
        let found_clone = found.clone();
        let output_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let curr = *current_clone.lock().unwrap();
                let fnd = *found_clone.lock().unwrap();
                if curr as usize >= total {
                    break;
                }
                print!("\r Current [{}/{}] Found: {}   ", curr, total, fnd);
                std::io::stdout().flush().ok();
            }
        });
        
        // Scan tasks
        let mut handles = Vec::new();
        
        for ip_int in start_ip..=end_ip {
            let semaphore_clone = semaphore.clone();
            let found_clone = found.clone();
            let current_clone = current.clone();
            let file_clone = file.clone();
            let net_tools_clone = self.net_tools.clone();
            let config_clone = self.config.clone();
            
            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.unwrap();
                let ip_str = net_tools_clone.int2ip(ip_int);
                let addr = format!("{}:{}", ip_str, config_clone.scan_port);
                
                match timeout(
                    Duration::from_secs_f64(config_clone.scan_timeout),
                    TcpStream::connect(&addr),
                ).await {
                    Ok(Ok(_stream)) => {
                        // Connection successful
                        let mut file_guard = file_clone.lock().unwrap();
                        writeln!(file_guard, "{}:{}", ip_str, config_clone.scan_port).ok();
                        drop(file_guard);
                        
                        *found_clone.lock().unwrap() += 1;
                    }
                    _ => {
                        // Connection failed or timeout
                    }
                }
                
                *current_clone.lock().unwrap() += 1;
                drop(permit);
            });
            
            handles.push(handle);
        }
        
        // Wait for all scans to complete
        for handle in handles {
            handle.await.ok();
        }
        
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

