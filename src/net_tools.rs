use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct NetTools;

impl NetTools {
    pub fn new() -> Self {
        Self
    }

    pub fn is_ip(&self, address: &str) -> bool {
        address.parse::<Ipv4Addr>().is_ok()
    }

    pub fn ip2int(&self, ip: &str) -> Option<u32> {
        let addr: Ipv4Addr = ip.parse().ok()?;
        let octets = addr.octets();
        // Convert IP to integer: a.b.c.d -> (a<<24) | (b<<16) | (c<<8) | d
        Some((u32::from(octets[0]) << 24) | 
             (u32::from(octets[1]) << 16) | 
             (u32::from(octets[2]) << 8) | 
             u32::from(octets[3]))
    }

    pub fn int2ip(&self, integer: u32) -> String {
        let a = (integer >> 24) & 0xFF;
        let b = (integer >> 16) & 0xFF;
        let c = (integer >> 8) & 0xFF;
        let d = integer & 0xFF;
        format!("{}.{}.{}.{}", a, b, c, d)
    }

    pub fn is_range(&self, string: &str) -> bool {
        if string.contains('-') {
            let parts: Vec<&str> = string.split('-').collect();
            if parts.len() == 2 {
                return self.is_ip(parts[0].trim()) && self.is_ip(parts[1].trim());
            }
        } else if string.matches('*').count() >= 1 && string.matches('*').count() <= 3 {
            let test_ip = string.replace('*', "0");
            return self.is_ip(&test_ip);
        }
        false
    }

    pub fn convert_range(&self, string: &str) -> Option<(u32, u32)> {
        if string.contains('-') {
            let parts: Vec<&str> = string.split('-').collect();
            if parts.len() == 2 {
                let start = self.ip2int(parts[0].trim())?;
                let end = self.ip2int(parts[1].trim())?;
                return Some((start.min(end), start.max(end)));
            }
        } else if string.matches('*').count() >= 1 && string.matches('*').count() <= 3 {
            let start_str = string.replace('*', "0");
            let end_str = string.replace('*', "255");
            let start = self.ip2int(&start_str)?;
            let end = self.ip2int(&end_str)?;
            return Some((start, end));
        }
        None
    }

    pub fn convert_ip(&self, string: &str) -> Option<u32> {
        self.ip2int(string.trim())
    }
}

