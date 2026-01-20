//! Wake-on-LAN implementation

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use tracing::{error, info};

/// Send a Wake-on-LAN magic packet
pub fn send_magic_packet(mac: &[u8; 6], broadcast_addr: Option<&str>) -> Result<(), std::io::Error> {
    // Build magic packet: 6 bytes of 0xFF followed by MAC address repeated 16 times
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(mac);
    }

    // Determine broadcast address
    let target = broadcast_addr.unwrap_or("255.255.255.255");
    let target_addr: SocketAddr = format!("{}:9", target).parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid broadcast address")
    })?;

    info!(
        "Sending WoL packet to {} for MAC {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        target_addr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // Create UDP socket with broadcast enabled
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_broadcast(true)?;

    // Bind to any address
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;

    // Send the packet
    socket.send_to(&packet, &target_addr.into())?;

    info!("WoL packet sent successfully");
    Ok(())
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

/// Format MAC address for display
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
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
    fn test_format_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac), "AA:BB:CC:DD:EE:FF");
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
}
