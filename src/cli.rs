use std::io::{self, Write};
use crate::MainEngine;
use crate::scan_engine::ScanEngine;
use crate::brute_engine::BruteEngine;
use std::sync::Arc;

pub async fn run(engine: &mut MainEngine) -> anyhow::Result<()> {
    loop {
        print!("+> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = input.split_whitespace().collect();
        let command = parts[0].to_lowercase();
        let args = &parts[1..];
        
        match command.as_str() {
            "exit" | "quit" | "q" => {
                if engine.config.auto_save {
                    engine.config.save(&engine.files)?;
                }
                println!("Bye.");
                break;
            }
            "clear" | "cls" => {
                engine.display.clear_screen(&engine.config);
            }
            "disclaimer" => {
                engine.display.disclaimer();
            }
            "scan" => {
                if let Some(range) = args.first() {
                    if engine.net_tools.is_range(range) {
                        engine.config.scan_range = range.to_string();
                        println!("\n\t[OK]\n");
                    } else {
                        println!("\n\t[ERROR]\n");
                    }
                }
                println!();
                let scan_engine = ScanEngine::new(
                    Arc::new(engine.config.clone()),
                    Arc::new(engine.files.clone()),
                    Arc::new(engine.net_tools.clone()),
                );
                if let Err(e) = scan_engine.start().await {
                    eprintln!("Scan error: {}", e);
                }
            }
            "brute" => {
                println!();
                let brute_engine = BruteEngine::new(
                    Arc::new(engine.config.clone()),
                    Arc::new(engine.files.clone()),
                    Arc::new(engine.net_tools.clone()),
                );
                if let Err(e) = brute_engine.start().await {
                    eprintln!("Brute error: {}", e);
                }
            }
            "set" => {
                if args.len() == 2 {
                    let key = args[0].to_lowercase();
                    let value = args[1];
                    let mut ok = false;
                    
                    match key.as_str() {
                        "scan_range" => {
                            if engine.net_tools.is_range(value) {
                                engine.config.scan_range = value.to_string();
                                ok = true;
                            }
                        }
                        "scan_threads" | "brute_threads" | "scan_port" => {
                            if let Ok(num) = value.parse::<u16>() {
                                match key.as_str() {
                                    "scan_threads" => {
                                        engine.config.scan_threads = num as usize;
                                        ok = true;
                                    }
                                    "brute_threads" => {
                                        engine.config.brute_threads = num as usize;
                                        ok = true;
                                    }
                                    "scan_port" => {
                                        engine.config.scan_port = num;
                                        ok = true;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "scan_timeout" | "brute_timeout" => {
                            if let Ok(num) = value.parse::<f64>() {
                                match key.as_str() {
                                    "scan_timeout" => {
                                        engine.config.scan_timeout = num;
                                        ok = true;
                                    }
                                    "brute_timeout" => {
                                        engine.config.brute_timeout = num;
                                        ok = true;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "auto_brute" | "auto_save" => {
                            let bool_val = value.to_lowercase() == "true";
                            match key.as_str() {
                                "auto_brute" => {
                                    engine.config.auto_brute = bool_val;
                                    ok = true;
                                }
                                "auto_save" => {
                                    engine.config.auto_save = bool_val;
                                    ok = true;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                    
                    if ok {
                        println!("\n\t[OK]\n");
                        if engine.config.auto_save {
                            engine.config.save(&engine.files)?;
                        }
                    } else {
                        println!("\n\t[ERROR]\n");
                    }
                } else {
                    println!("\n\t[ERROR]\n");
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                engine.display.clear_screen(&engine.config);
            }
            "show" => {
                if let Some(what) = args.first() {
                    let what = what.to_lowercase();
                    match what.as_str() {
                        "results" | "result" | "brute" => {
                            println!("\nBrute Results");
                            engine.display.delimiter("Brute Results");
                            let path = engine.files.get_results_path();
                            if engine.files.file_exists(&path) {
                                if let Ok(content) = engine.files.file_get_contents(&path) {
                                    for line in content.lines() {
                                        if !line.trim().is_empty() {
                                            println!("{}", line);
                                        }
                                    }
                                }
                            }
                            engine.display.delimiter("Brute Results");
                        }
                        "ips" | "scan" | "ip" => {
                            println!("\nScan Results");
                            engine.display.delimiter("Scan Results");
                            let path = engine.files.get_ips_path();
                            if engine.files.file_exists(&path) {
                                if let Ok(content) = engine.files.file_get_contents(&path) {
                                    for line in content.lines() {
                                        if !line.trim().is_empty() {
                                            println!("{}", line);
                                        }
                                    }
                                }
                            }
                            engine.display.delimiter("Scan Results");
                        }
                        "password" | "passwords" | "pass" => {
                            println!("\nPasswords");
                            engine.display.delimiter("Passwords");
                            let path = engine.files.get_passwords_path();
                            if engine.files.file_exists(&path) {
                                if let Ok(content) = engine.files.file_get_contents(&path) {
                                    for line in content.lines() {
                                        if !line.trim().is_empty() {
                                            println!("{}", line);
                                        }
                                    }
                                }
                            }
                            engine.display.delimiter("Passwords");
                        }
                        _ => {
                            println!("\nSettings");
                            engine.display.delimiter("Settings");
                            println!("scan_range = {}", engine.config.scan_range);
                            println!("scan_port = {}", engine.config.scan_port);
                            println!("scan_timeout = {}", engine.config.scan_timeout);
                            println!("scan_threads = {}", engine.config.scan_threads);
                            println!("brute_threads = {}", engine.config.brute_threads);
                            println!("brute_timeout = {}", engine.config.brute_timeout);
                            println!("auto_save = {}", engine.config.auto_save);
                            println!("auto_brute = {}", engine.config.auto_brute);
                            engine.display.delimiter("Settings");
                            println!();
                        }
                    }
                } else {
                    println!("\nSettings");
                    engine.display.delimiter("Settings");
                    println!("scan_range = {}", engine.config.scan_range);
                    println!("scan_port = {}", engine.config.scan_port);
                    println!("scan_timeout = {}", engine.config.scan_timeout);
                    println!("scan_threads = {}", engine.config.scan_threads);
                    println!("brute_threads = {}", engine.config.brute_threads);
                    println!("brute_timeout = {}", engine.config.brute_timeout);
                    println!("auto_save = {}", engine.config.auto_save);
                    println!("auto_brute = {}", engine.config.auto_brute);
                    engine.display.delimiter("Settings");
                    println!();
                }
            }
            "add" => {
                if args.len() == 2 {
                    let value = args[0];
                    let file_key = args[1].to_lowercase();
                    
                    let path = match file_key.as_str() {
                        "results" => Some(engine.files.get_results_path()),
                        "ips" => Some(engine.files.get_ips_path()),
                        "passwords" => Some(engine.files.get_passwords_path()),
                        _ => None,
                    };
                    
                    if let Some(path) = path {
                        engine.files.file_write(&path, format!("{}\n", value).as_bytes(), "i")?;
                        println!("\n\t[OK]\n");
                    } else {
                        println!("\n\t[ERROR]\n");
                    }
                } else {
                    println!("\n\t[ERROR]\n");
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                engine.display.clear_screen(&engine.config);
            }
            "flush" => {
                if let Some(file_key) = args.first() {
                    let file_key = file_key.to_lowercase();
                    
                    if file_key == "all" || file_key == "everything" {
                        engine.files.file_write(&engine.files.get_results_path(), b"", "w")?;
                        engine.files.file_write(&engine.files.get_ips_path(), b"", "w")?;
                        engine.files.file_write(&engine.files.get_passwords_path(), b"", "w")?;
                        println!("\n\t[OK]\n");
                    } else {
                        let path = match file_key.as_str() {
                            "results" => Some(engine.files.get_results_path()),
                            "ips" => Some(engine.files.get_ips_path()),
                            "passwords" => Some(engine.files.get_passwords_path()),
                            _ => None,
                        };
                        
                        if let Some(path) = path {
                            engine.files.file_write(&path, b"", "w")?;
                            println!("\n\t[OK]\n");
                        } else {
                            println!("\n\t[ERROR]\n");
                        }
                    }
                } else {
                    println!("\n\t[ERROR]\n");
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                engine.display.clear_screen(&engine.config);
            }
            _ => {
                println!("\n\tNope.\n");
            }
        }
    }
    
    Ok(())
}

