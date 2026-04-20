//! Network scanning helpers for auto-discovering reachable agents.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

const MAX_SCAN_HOSTS: usize = 1024;
const CONNECT_TIMEOUT_MS: u64 = 300;
const MAX_CONCURRENT_SCANS: usize = 64;

pub async fn scan_subnet(cidr_or_ip: &str, port: u16) -> Result<Vec<String>, String> {
    let hosts = expand_hosts(cidr_or_ip)?;
    let mut results = Vec::new();
    let mut pending = JoinSet::new();

    for ip in hosts {
        while pending.len() >= MAX_CONCURRENT_SCANS {
            if let Some(found_ip) = collect_next_result(&mut pending).await? {
                results.push(found_ip);
            }
        }

        pending.spawn(async move { try_connect(ip, port).await });
    }

    while let Some(found_ip) = collect_next_result(&mut pending).await? {
        results.push(found_ip);
    }

    results.sort_by_key(|ip| ip.parse::<Ipv4Addr>().ok().map(u32::from).unwrap_or_default());
    Ok(results)
}

async fn collect_next_result(
    pending: &mut JoinSet<Result<Option<String>, String>>,
) -> Result<Option<String>, String> {
    match pending.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(format!("扫描任务失败: {}", e)),
        None => Ok(None),
    }
}

async fn try_connect(ip: Ipv4Addr, port: u16) -> Result<Option<String>, String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match timeout(Duration::from_millis(CONNECT_TIMEOUT_MS), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(Some(ip.to_string())),
        Ok(Err(_)) | Err(_) => Ok(None),
    }
}

fn expand_hosts(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("请输入要扫描的网段，例如 10.0.0.0/24".to_string());
    }

    let (base_ip, prefix) = if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
        let ip = ip_part
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| "网段格式无效，请使用 IPv4 CIDR，例如 10.0.0.0/24".to_string())?;
        let prefix = prefix_part
            .trim()
            .parse::<u8>()
            .map_err(|_| "CIDR 前缀无效".to_string())?;
        if prefix > 32 {
            return Err("CIDR 前缀必须在 0-32 之间".to_string());
        }
        (ip, prefix)
    } else {
        let ip = trimmed
            .parse::<Ipv4Addr>()
            .map_err(|_| "网段格式无效，请使用 IPv4 地址或 CIDR".to_string())?;
        (ip, 32)
    };

    let host_count_u128 = 1u128 << (32 - prefix as u32);
    if host_count_u128 > MAX_SCAN_HOSTS as u128 {
        return Err(format!(
            "扫描范围过大（{} 个地址），请缩小到最多 {} 个地址",
            host_count_u128, MAX_SCAN_HOSTS
        ));
    }

    let host_count = host_count_u128 as u32;
    let base = u32::from(base_ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let network = base & mask;

    let mut hosts = Vec::new();
    if prefix == 32 {
        hosts.push(Ipv4Addr::from(base));
        return Ok(hosts);
    }

    let (start, end) = if host_count <= 2 {
        (network, network + host_count - 1)
    } else {
        (network + 1, network + host_count - 2)
    };

    for value in start..=end {
        hosts.push(Ipv4Addr::from(value));
    }

    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::expand_hosts;

    #[test]
    fn expands_single_ip() {
        let hosts = expand_hosts("10.0.0.130").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].to_string(), "10.0.0.130");
    }

    #[test]
    fn expands_cidr_hosts_without_network_and_broadcast() {
        let hosts = expand_hosts("10.0.0.0/30").unwrap();
        let values: Vec<String> = hosts.into_iter().map(|ip| ip.to_string()).collect();
        assert_eq!(values, vec!["10.0.0.1", "10.0.0.2"]);
    }
}
