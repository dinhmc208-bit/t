mod config;
mod des;
mod display;
mod files;
mod net_tools;
mod rfb;
mod scan_engine;
mod brute_engine;
mod cli;

use anyhow::Result;
use config::Config;
use display::Display;
use files::FilesHandler;
use net_tools::NetTools;

const VERSION: &str = "1.0.1";
const CODENAME: &str = "HotCheesePizza";

pub struct MainEngine {
    pub config: Config,
    pub files: FilesHandler,
    pub net_tools: NetTools,
    pub display: Display,
}

impl MainEngine {
    pub fn new() -> Result<Self> {
        let files = FilesHandler::new();
        let net_tools = NetTools::new();
        let display = Display::new();
        
        // Deploy folders and files
        files.deploy_folders()?;
        files.deploy_files()?;
        
        // Load config
        let config = Config::load(&files)?;
        
        Ok(Self {
            config,
            files,
            net_tools,
            display,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        self.display.clear_screen(&self.config);
        cli::run(self).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut engine = MainEngine::new()?;
    
    if let Err(e) = engine.start().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}

