use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use crate::des::vnc_des_encrypt;

pub struct RFBProtocol {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub timeout: Duration,
    pub shared: u8,
    
    pub connected: bool,
    pub rfb: bool,
    pub null: bool,
    pub name: Option<String>,
    pub fail_message: Option<String>,
}

impl RFBProtocol {
    pub fn new(host: &str, password: &str, port: u16, timeout_secs: f64) -> Self {
        Self {
            host: host.to_string(),
            port,
            password: password.to_string(),
            timeout: Duration::from_secs_f64(timeout_secs),
            shared: 1,
            connected: false,
            rfb: false,
            null: false,
            name: None,
            fail_message: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), String> {
        self.conn_init().await?;
        self.client_auth().await?;
        Ok(())
    }

    async fn conn_init(&mut self) -> Result<(), String> {
        // This is a placeholder - actual connection happens in client_auth
        Ok(())
    }

    async fn client_auth(&mut self) -> Result<(), String> {
        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;
        
        let mut stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| "Connection timeout")?
            .map_err(|e| format!("Connection failed: {}", e))?;
        
        // Read RFB version
        let mut buf = vec![0u8; 12];
        timeout(self.timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| "Read timeout")?
            .map_err(|e| format!("Read error: {}", e))?;
        
        if &buf[..3] != b"RFB" {
            return Err("Not RFB protocol".to_string());
        }
        
        self.rfb = true;
        
        // Send client version
        stream.write_all(b"RFB 003.003\n")
            .await
            .map_err(|e| format!("Write error: {}", e))?;
        
        // Read auth method
        let mut method_buf = vec![0u8; 4];
        timeout(self.timeout, stream.read_exact(&mut method_buf))
            .await
            .map_err(|_| "Read timeout")?
            .map_err(|e| format!("Read error: {}", e))?;
        
        let mut cursor = Cursor::new(method_buf);
        let method = ReadBytesExt::read_u32::<BigEndian>(&mut cursor).unwrap();
        
        match method {
            0 => {
                // Failure
                let mut len_buf = vec![0u8; 4];
                timeout(self.timeout, stream.read_exact(&mut len_buf))
                    .await
                    .map_err(|_| "Read timeout")?
                    .map_err(|e| format!("Read error: {}", e))?;
                
                let mut len_cursor = Cursor::new(len_buf);
                let len = ReadBytesExt::read_u32::<BigEndian>(&mut len_cursor).unwrap();
                
                let mut msg_buf = vec![0u8; len as usize];
                timeout(self.timeout, stream.read_exact(&mut msg_buf))
                    .await
                    .map_err(|_| "Read timeout")?
                    .map_err(|e| format!("Read error: {}", e))?;
                
                let msg = String::from_utf8_lossy(&msg_buf).to_string();
                self.fail_message = Some(msg.clone());
                return Err(msg);
            }
            1 => {
                // None
                self.null = true;
                self.client_init(&mut stream).await?;
            }
            2 => {
                // VNC Auth
                self.vnc_auth(&mut stream).await?;
            }
            _ => {
                return Err("Unsupported auth method".to_string());
            }
        }
        
        Ok(())
    }

    async fn vnc_auth(&mut self, stream: &mut TcpStream) -> Result<(), String> {
        let mut challenge = vec![0u8; 16];
        timeout(self.timeout, stream.read_exact(&mut challenge))
            .await
            .map_err(|_| "Read timeout")?
            .map_err(|e| format!("Read error: {}", e))?;
        
        self.send_password(stream, &challenge).await?;
        
        let mut result_buf = vec![0u8; 4];
        timeout(self.timeout, stream.read_exact(&mut result_buf))
            .await
            .map_err(|_| "Read timeout")?
            .map_err(|e| format!("Read error: {}", e))?;
        
        let mut cursor = Cursor::new(result_buf);
        let result = ReadBytesExt::read_u32::<BigEndian>(&mut cursor).unwrap();
        
        match result {
            0 => {
                self.client_init(stream).await?;
                Ok(())
            }
            1 => Err("WRONG PASSWORD".to_string()),
            _ => Err(format!("Unknown auth result: {}", result)),
        }
    }

    async fn client_init(&mut self, stream: &mut TcpStream) -> Result<(), String> {
        self.connected = true;
        
        stream.write_u8(self.shared)
            .await
            .map_err(|e| format!("Write error: {}", e))?;
        
        let mut buf = vec![0u8; 24];
        timeout(self.timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| "Read timeout")?
            .map_err(|e| format!("Read error: {}", e))?;
        
        let mut cursor = Cursor::new(&buf);
        let _width = ReadBytesExt::read_u16::<BigEndian>(&mut cursor).unwrap();
        let _height = ReadBytesExt::read_u16::<BigEndian>(&mut cursor).unwrap();
        // Skip 16 bytes for pixformat
        let mut pixformat = [0u8; 16];
        std::io::Read::read_exact(&mut cursor, &mut pixformat).unwrap();
        let namelen = ReadBytesExt::read_u32::<BigEndian>(&mut cursor).unwrap();
        
        let mut name_buf = vec![0u8; namelen as usize];
        timeout(self.timeout, stream.read_exact(&mut name_buf))
            .await
            .map_err(|_| "Read timeout")?
            .map_err(|e| format!("Read error: {}", e))?;
        
        self.name = Some(String::from_utf8_lossy(&name_buf).to_string());
        
        Ok(())
    }

    async fn send_password(&self, stream: &mut TcpStream, challenge: &[u8]) -> Result<(), String> {
        let mut password = self.password.clone();
        password.push_str(&"\0".repeat(8));
        let password_bytes = password.as_bytes();
        let password_8 = &password_bytes[..8.min(password_bytes.len())];
        
        let response = vnc_des_encrypt(
            std::str::from_utf8(password_8).unwrap(),
            challenge,
        );
        
        stream.write_all(&response)
            .await
            .map_err(|e| format!("Write error: {}", e))?;
        
        stream.flush().await.map_err(|e| format!("Flush error: {}", e))?;
        
        Ok(())
    }
}

