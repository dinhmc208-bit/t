use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};

#[derive(Clone)]
pub struct FilesHandler {
    pub root_path: PathBuf,
}

impl FilesHandler {
    pub fn new() -> Self {
        Self {
            root_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }

    pub fn deploy_folders(&self) -> Result<()> {
        let folders = ["output", "input", "bin"];
        for folder in folders.iter() {
            let path = self.root_path.join(folder);
            self.mkdir(&path)?;
        }
        Ok(())
    }

    pub fn deploy_files(&self) -> Result<()> {
        // Create empty files if they don't exist
        let files = [
            ("output/results.txt", ""),
            ("output/ips.txt", ""),
            ("input/passwords.txt", "1\n12\n123\n1234\n12345\n123456\n1234567\n12345678\nletmein\nadmin\nadminist\npassword\n1212\n"),
            ("bin/config.conf", ""),
        ];

        for (rel_path, default_content) in files.iter() {
            let path = self.root_path.join(rel_path);
            if !self.file_exists(&path) {
                self.file_write(&path, default_content.as_bytes(), "w")?;
            }
        }

        // Initialize config if empty
        let config_path = self.get_config_path();
        if self.file_empty(&config_path)? {
            let default_config = crate::config::Config::default();
            let config_map = default_config.to_map();
            let config_data = bincode::serialize(&config_map)?;
            self.file_write(&config_path, &config_data, "b")?;
        }

        Ok(())
    }

    pub fn file_get_contents(&self, path: &Path) -> Result<String> {
        // Try reading as UTF-8 first, if fails, try as bytes and convert
        match fs::read_to_string(path) {
            Ok(content) => Ok(content),
            Err(_) => {
                // If UTF-8 fails, read as bytes and try to convert
                let bytes = fs::read(path)
                    .context(format!("Failed to read file: {:?}", path))?;
                String::from_utf8(bytes)
                    .map_err(|_| anyhow::anyhow!("File contains invalid UTF-8"))
            }
        }
    }

    pub fn file_get_contents_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        fs::read(path)
            .context(format!("Failed to read file: {:?}", path))
    }

    pub fn file_write(&self, path: &Path, data: &[u8], mode: &str) -> Result<()> {
        if mode == "i" {
            // Insert mode - prepend to file
            let old_content = if self.file_exists(path) {
                fs::read(path).unwrap_or_default()
            } else {
                Vec::new()
            };
            let mut new_data = data.to_vec();
            new_data.push(b'\n');
            new_data.extend_from_slice(&old_content);
            fs::write(path, new_data)?;
        } else if mode == "b" || mode == "wb" {
            // Binary mode
            fs::write(path, data)?;
        } else {
            // Text mode
            let content = String::from_utf8_lossy(data);
            fs::write(path, content.as_bytes())?;
        }
        Ok(())
    }

    pub fn file_empty(&self, path: &Path) -> Result<bool> {
        if !self.file_exists(path) {
            return Ok(true);
        }
        let metadata = fs::metadata(path)?;
        Ok(metadata.len() == 0)
    }

    pub fn file_exists(&self, path: &Path) -> bool {
        path.exists() && path.is_file()
    }

    pub fn dir_exists(&self, path: &Path) -> bool {
        path.exists() && path.is_dir()
    }

    pub fn mkdir(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    pub fn get_results_path(&self) -> PathBuf {
        self.root_path.join("output").join("results.txt")
    }

    pub fn get_ips_path(&self) -> PathBuf {
        self.root_path.join("output").join("ips.txt")
    }

    pub fn get_passwords_path(&self) -> PathBuf {
        self.root_path.join("input").join("passwords.txt")
    }

    pub fn get_config_path(&self) -> PathBuf {
        self.root_path.join("bin").join("config.conf")
    }
}

