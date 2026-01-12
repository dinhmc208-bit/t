use crate::config::Config;

pub struct Display;

impl Display {
    pub fn new() -> Self {
        Self
    }

    pub fn clear_screen(&self, config: &Config) {
        #[cfg(windows)]
        std::process::Command::new("cmd")
            .args(&["/C", "cls"])
            .status()
            .ok();
        
        #[cfg(not(windows))]
        std::process::Command::new("clear")
            .status()
            .ok();
        
        self.banner(config);
    }

    pub fn banner(&self, config: &Config) {
        println!();
        println!("|>>>> - VNC Scanner - {} - {} - <<<<|", crate::VERSION, crate::CODENAME);
        println!("Scan Threads: {} <-> Scan Timeout: {} <-> Scan Port: {}", 
            config.scan_threads, config.scan_timeout, config.scan_port);
        println!("Brute Threads: {} <-> Brute Timeout: {} <-> Auto Brute: {}", 
            config.brute_threads, config.brute_timeout, config.auto_brute);
        println!("Scan Range: {} <-> Auto Save: {}", 
            config.scan_range, config.auto_save);
        println!();
    }

    pub fn delimiter(&self, string: &str) {
        println!("\n{}", "-".repeat(string.len()));
    }

    pub fn disclaimer(&self) {
        let disclaimer = r#"

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is not a hacking tool, this is a security assessment tool.
We do not encourage cracking or any other illicit activities that
put in danger the privacy or the informational integrity of others,
and we certainly do not want this tool to be misused.
!!! USE IT AT YOUR OWN RISK !!!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


"#;
        println!("{}", disclaimer);
    }
}

