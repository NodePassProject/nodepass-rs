use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemInfo {
    pub cpu: i32,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub netrx: u64,
    pub nettx: u64,
    pub diskr: u64,
    pub diskw: u64,
    pub sysup: u64,
}

#[cfg(target_os = "linux")]
pub fn get_linux_sys_info() -> SystemInfo {
    let mut info = SystemInfo {
        cpu: -1,
        ..Default::default()
    };

    // CPU usage
    fn read_stat() -> (u64, u64) {
        let data = match std::fs::read_to_string("/proc/stat") {
            Ok(d) => d,
            Err(_) => return (0, 0),
        };
        for line in data.lines() {
            if line.starts_with("cpu ") {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let mut total = 0u64;
                let mut idle = 0u64;
                for (i, field) in fields[1..].iter().enumerate() {
                    let val: u64 = field.parse().unwrap_or(0);
                    total += val;
                    if i == 3 {
                        idle = val;
                    }
                }
                return (idle, total);
            }
        }
        (0, 0)
    }

    let (idle1, total1) = read_stat();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let (idle2, total2) = read_stat();

    let delta_idle = idle2.saturating_sub(idle1);
    let delta_total = total2.saturating_sub(total1);
    if delta_total > 0 {
        info.cpu = ((delta_total - delta_idle) * 100 / delta_total).min(100) as i32;
    }

    // Memory
    if let Ok(data) = std::fs::read_to_string("/proc/meminfo") {
        let mut mem_total = 0u64;
        let mut mem_available = 0u64;
        let mut swap_total = 0u64;
        let mut swap_free = 0u64;

        for line in data.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                let val: u64 = fields[1].parse().unwrap_or(0) * 1024;
                match fields[0] {
                    "MemTotal:" => mem_total = val,
                    "MemAvailable:" => mem_available = val,
                    "SwapTotal:" => swap_total = val,
                    "SwapFree:" => swap_free = val,
                    _ => {}
                }
            }
        }
        info.mem_total = mem_total;
        info.mem_used = mem_total.saturating_sub(mem_available);
        info.swap_total = swap_total;
        info.swap_used = swap_total.saturating_sub(swap_free);
    }

    // Network
    if let Ok(data) = std::fs::read_to_string("/proc/net/dev") {
        for line in data.lines().skip(2) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10 {
                let ifname = fields[0].trim_end_matches(':');
                if ifname.starts_with("lo") || ifname.starts_with("veth")
                    || ifname.starts_with("docker") || ifname.starts_with("podman")
                    || ifname.starts_with("br-") || ifname.starts_with("virbr")
                {
                    continue;
                }
                info.netrx += fields[1].parse::<u64>().unwrap_or(0);
                info.nettx += fields[9].parse::<u64>().unwrap_or(0);
            }
        }
    }

    // Disk
    if let Ok(data) = std::fs::read_to_string("/proc/diskstats") {
        let digit_re = regex::Regex::new(r"\d+$").unwrap();
        for line in data.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 14 {
                let device = fields[2];
                if device.contains("loop") || device.contains("ram")
                    || device.starts_with("dm-") || device.starts_with("md")
                {
                    continue;
                }
                if digit_re.is_match(device) {
                    continue;
                }
                info.diskr += fields[5].parse::<u64>().unwrap_or(0) * 512;
                info.diskw += fields[9].parse::<u64>().unwrap_or(0) * 512;
            }
        }
    }

    // Uptime
    if let Ok(data) = std::fs::read_to_string("/proc/uptime") {
        let fields: Vec<&str> = data.split_whitespace().collect();
        if !fields.is_empty() {
            info.sysup = fields[0].parse::<f64>().unwrap_or(0.0) as u64;
        }
    }

    info
}

#[cfg(not(target_os = "linux"))]
pub fn get_linux_sys_info() -> SystemInfo {
    SystemInfo {
        cpu: -1,
        ..Default::default()
    }
}
