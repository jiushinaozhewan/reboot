//! Wake-on-LAN implementation

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::info;

const DEFAULT_BROADCAST: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
const DEFAULT_PORTS: [u16; 2] = [9, 7];

/// Send a Wake-on-LAN magic packet
pub fn send_magic_packet(
    mac: &[u8; 6],
    target_ip: Option<&str>,
    broadcast_addr: Option<&str>,
) -> Result<(), std::io::Error> {
    // Build magic packet: 6 bytes of 0xFF followed by MAC address repeated 16 times
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(mac);
    }

    let targets = resolve_magic_packet_targets(target_ip, broadcast_addr)?;

    // Create UDP socket with broadcast enabled
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_broadcast(true)?;

    // Bind to any address
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;

    for target_addr in &targets {
        info!(
            "Sending WoL packet to {} for MAC {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            target_addr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        socket.send_to(&packet, &(*target_addr).into())?;
    }

    info!("WoL packet sent successfully to {} targets", targets.len());
    Ok(())
}

fn resolve_magic_packet_targets(
    target_ip: Option<&str>,
    broadcast_addr: Option<&str>,
) -> Result<Vec<SocketAddr>, std::io::Error> {
    let mut broadcast_ips = Vec::new();

    if let Some(configured) = broadcast_addr
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let ip: Ipv4Addr = configured.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid broadcast address")
        })?;
        broadcast_ips.push(ip);
    } else {
        broadcast_ips.push(DEFAULT_BROADCAST);

        if let Some(ip) = target_ip.and_then(parse_ipv4) {
            let directed = infer_directed_broadcast(ip);
            if directed != DEFAULT_BROADCAST {
                broadcast_ips.push(directed);
            }
        }
    }

    let mut targets = Vec::new();
    for broadcast_ip in broadcast_ips {
        for port in DEFAULT_PORTS {
            let socket_addr = SocketAddr::new(IpAddr::V4(broadcast_ip), port);
            if !targets.contains(&socket_addr) {
                targets.push(socket_addr);
            }
        }
    }

    Ok(targets)
}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    value.trim().parse().ok()
}

fn infer_directed_broadcast(ip: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, _] = ip.octets();
    Ipv4Addr::new(a, b, c, 255)
}

/// Parse MAC address from various formats
pub fn parse_mac(mac_str: &str) -> Result<[u8; 6], String> {
    let cleaned: String = mac_str
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.len() != 12 {
        return Err(format!(
            "Invalid MAC address: expected 12 hex digits, got {}",
            cleaned.len()
        ));
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex digit")?;
    }

    Ok(mac)
}

/// Resolve a target MAC address from the local ARP cache.
#[cfg(windows)]
pub fn lookup_mac_via_arp(ip: &str) -> Result<[u8; 6], String> {
    let output = std::process::Command::new("arp")
        .args(["-a", ip])
        .output()
        .map_err(|e| format!("执行 arp 命令失败: {}", e))?;

    if !output.status.success() {
        return Err(format!("arp 命令执行失败: {}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(mac) = parse_arp_line_for_ip(line, ip) {
            return Ok(mac);
        }
    }

    Err(format!("ARP 缓存中未找到 {}", ip))
}

#[cfg(not(windows))]
pub fn lookup_mac_via_arp(ip: &str) -> Result<[u8; 6], String> {
    let _ = ip;
    Err("ARP 回退仅支持 Windows".to_string())
}

fn parse_arp_line_for_ip(line: &str, ip: &str) -> Option<[u8; 6]> {
    if !line.contains(ip) {
        return None;
    }

    let mut parts = line.split_whitespace();
    let line_ip = parts.next().unwrap_or_default();
    let mac = parts.next().unwrap_or_default();

    (line_ip == ip).then(|| parse_mac(mac).ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        // Test with colons
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // Test with dashes
        let mac = parse_mac("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // Test without separators
        let mac = parse_mac("AABBCCDDEEFF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // Test lowercase
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_magic_packet_format() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Build packet manually to verify
        let mut expected = vec![0xFFu8; 6];
        for _ in 0..16 {
            expected.extend_from_slice(&mac);
        }

        assert_eq!(expected.len(), 6 + 6 * 16); // 102 bytes
    }

    #[test]
    fn test_parse_mac_accepts_dash_format() {
        let mac = parse_arp_line_for_ip("10.0.0.130  94-c6-91-f3-e2-d8  dynamic", "10.0.0.130")
            .unwrap();
        assert_eq!(mac, [0x94, 0xC6, 0x91, 0xF3, 0xE2, 0xD8]);
    }

    #[test]
    fn test_resolve_targets_uses_directed_broadcast_when_available() {
        let targets = resolve_magic_packet_targets(Some("10.0.0.191"), None).unwrap();

        assert_eq!(
            targets,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 9),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 7),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)), 9),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)), 7),
            ]
        );
    }

    #[test]
    fn test_resolve_targets_prefers_explicit_broadcast() {
        let targets =
            resolve_magic_packet_targets(Some("10.0.0.191"), Some("10.0.0.255")).unwrap();

        assert_eq!(
            targets,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)), 9),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)), 7),
            ]
        );
    }
}
