use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::files::FilesHandler;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan_range: String,
    pub scan_port: u16,
    pub scan_timeout: f64,
    pub scan_threads: usize,
    pub brute_threads: usize,
    pub brute_timeout: f64,
    pub auto_save: bool,
    pub auto_brute: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_range: "192.168.*.*".to_string(),
            scan_port: 5900,
            scan_timeout: 15.0,
            scan_threads: 20000, // Max 20k threads
            brute_threads: 20000,
            brute_timeout: 15.0,
            auto_save: true,
            auto_brute: true,
        }
    }
}

impl Config {
    pub fn load(files: &FilesHandler) -> Result<Self> {
        let config_path = files.get_config_path();
        
        if files.file_exists(&config_path) && !files.file_empty(&config_path)? {
            // Try reading as binary first (bincode), then as text (JSON)
            let bytes = files.file_get_contents_bytes(&config_path)?;
            
            let config_map: HashMap<String, String> = if let Ok(map) = bincode::deserialize(&bytes) {
                map
            } else {
                // Try as UTF-8 string for JSON
                match String::from_utf8(bytes) {
                    Ok(content) => {
                        serde_json::from_str(&content)
                            .context("Failed to parse config file as JSON")?
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!("Config file is neither valid bincode nor valid UTF-8 JSON"));
                    }
                }
            };
            
            Ok(Self::from_map(config_map))
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, files: &FilesHandler) -> Result<()> {
        let config_path = files.get_config_path();
        let config_map = self.to_map();
        let data = bincode::serialize(&config_map)?;
        files.file_write(&config_path, &data, "b")?;
        Ok(())
    }

    fn from_map(map: HashMap<String, String>) -> Self {
        let default = Self::default();
        Self {
            scan_range: map.get("scan_range")
                .cloned()
                .unwrap_or(default.scan_range),
            scan_port: map.get("scan_port")
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.scan_port),
            scan_timeout: map.get("scan_timeout")
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.scan_timeout),
            scan_threads: map.get("scan_threads")
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.scan_threads)
                .min(20000), // Cap at 20k
            brute_threads: map.get("brute_threads")
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.brute_threads)
                .min(20000), // Cap at 20k
            brute_timeout: map.get("brute_timeout")
                .and_then(|s| s.parse().ok())
                .unwrap_or(default.brute_timeout),
            auto_save: map.get("auto_save")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(default.auto_save),
            auto_brute: map.get("auto_brute")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(default.auto_brute),
        }
    }

    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("scan_range".to_string(), self.scan_range.clone());
        map.insert("scan_port".to_string(), self.scan_port.to_string());
        map.insert("scan_timeout".to_string(), self.scan_timeout.to_string());
        map.insert("scan_threads".to_string(), self.scan_threads.to_string());
        map.insert("brute_threads".to_string(), self.brute_threads.to_string());
        map.insert("brute_timeout".to_string(), self.brute_timeout.to_string());
        map.insert("auto_save".to_string(), self.auto_save.to_string());
        map.insert("auto_brute".to_string(), self.auto_brute.to_string());
        map
    }
}

// Removed const DEFAULT_CONFIG as it can't be used with String fields

