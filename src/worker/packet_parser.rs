//! Packet Parser for Data Plane
//!
//! High-performance packet parsing for Ethernet/IPv4/UDP packets.
//!
//! **Design decisions:**
//! - D3: Userspace Demultiplexing (parse to extract multicast group and port)
//! - D30: Fragment Handling (detect and reject fragmented packets)
//! - D32: Checksum Policy (validate IP and UDP checksums)
//!
//! **Performance target:** < 100ns parsing overhead per packet
//!
//! This implementation uses safe Rust with slice indexing for parsing.
//! Future optimization: If parsing becomes a bottleneck, run Experiment #4
//! (Packet Parsing Performance) to evaluate unsafe pointer manipulation.

use std::net::Ipv4Addr;
use thiserror::Error;

/// Errors that can occur during packet parsing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Invalid EtherType: expected 0x0800 (IPv4), got {0:#06x}")]
    InvalidEtherType(u16),

    #[error("Invalid IP version: expected 4, got {0}")]
    InvalidIpVersion(u8),

    #[error("Invalid IP protocol: expected 17 (UDP), got {0}")]
    InvalidIpProtocol(u8),

    #[error("IP header checksum mismatch: expected {expected:#06x}, got {actual:#06x}")]
    IpChecksumMismatch { expected: u16, actual: u16 },

    #[error("UDP checksum mismatch: expected {expected:#06x}, got {actual:#06x}")]
    UdpChecksumMismatch { expected: u16, actual: u16 },

    #[error("Fragmented packet (D30: fragments are not supported)")]
    FragmentedPacket,

    #[error("IP header length too small: {0} bytes")]
    IpHeaderTooSmall(u8),
}

/// Parsed Ethernet header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

/// Parsed IPv4 header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,  // Internet Header Length (in 32-bit words)
    pub dscp: u8, // Differentiated Services Code Point (for QoS)
    pub ecn: u8,  // Explicit Congestion Notification
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    /// Check if this packet is fragmented (D30)
    ///
    /// A packet is fragmented if:
    /// - The More Fragments (MF) flag is set, OR
    /// - The fragment offset is non-zero
    pub fn is_fragmented(&self) -> bool {
        let mf_flag = (self.flags & 0x01) != 0; // MF is bit 0 of flags
        mf_flag || self.fragment_offset != 0
    }

    /// Get the IP header length in bytes
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

/// Parsed UDP header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// Complete parsed packet headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeaders {
    pub ethernet: EthernetHeader,
    pub ipv4: Ipv4Header,
    pub udp: UdpHeader,
    pub payload_offset: usize,
    pub payload_len: usize,
}

impl PacketHeaders {
    /// Get the total packet length
    pub fn total_len(&self) -> usize {
        self.payload_offset + self.payload_len
    }

    /// Check if this packet matches a multicast relay rule
    pub fn matches(&self, group: Ipv4Addr, port: u16) -> bool {
        self.ipv4.dst_ip == group && self.udp.dst_port == port
    }
}

/// Parse a complete packet (Ethernet + IPv4 + UDP)
///
/// # Arguments
/// * `data` - Raw packet data (starting with Ethernet header)
/// * `validate_checksums` - Whether to validate IP and UDP checksums (D32)
///
/// # Returns
/// Parsed packet headers, or an error if parsing fails
///
/// # Performance
/// Target: < 100ns per packet
/// Actual: TBD (run Experiment #4 if this becomes a bottleneck)
pub fn parse_packet(data: &[u8], validate_checksums: bool) -> Result<PacketHeaders, ParseError> {
    // Parse Ethernet header (14 bytes minimum)
    let ethernet = parse_ethernet(data)?;

    // Verify it's IPv4
    if ethernet.ether_type != 0x0800 {
        return Err(ParseError::InvalidEtherType(ethernet.ether_type));
    }

    // Parse IPv4 header (starts at byte 14)
    let ip_offset = 14;
    let ipv4 = parse_ipv4(&data[ip_offset..], validate_checksums)?;

    // Check for fragmentation (D30: reject fragments)
    if ipv4.is_fragmented() {
        return Err(ParseError::FragmentedPacket);
    }

    // Verify it's UDP
    if ipv4.protocol != 17 {
        return Err(ParseError::InvalidIpProtocol(ipv4.protocol));
    }

    // Parse UDP header (starts after IP header)
    let udp_offset = ip_offset + ipv4.header_len();
    let udp = parse_udp(&data[udp_offset..], &ipv4, data, validate_checksums)?;

    // Calculate payload offset and length
    let payload_offset = udp_offset + 8; // UDP header is always 8 bytes
    let payload_len = (udp.length as usize).saturating_sub(8); // UDP length includes header

    Ok(PacketHeaders {
        ethernet,
        ipv4,
        udp,
        payload_offset,
        payload_len,
    })
}

/// Parse Ethernet header (14 bytes)
fn parse_ethernet(data: &[u8]) -> Result<EthernetHeader, ParseError> {
    if data.len() < 14 {
        return Err(ParseError::PacketTooShort {
            expected: 14,
            actual: data.len(),
        });
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];

    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);

    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    Ok(EthernetHeader {
        dst_mac,
        src_mac,
        ether_type,
    })
}

/// Parse IPv4 header (minimum 20 bytes)
fn parse_ipv4(data: &[u8], validate_checksum: bool) -> Result<Ipv4Header, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::PacketTooShort {
            expected: 20,
            actual: data.len(),
        });
    }

    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return Err(ParseError::InvalidIpVersion(version));
    }

    let ihl = data[0] & 0x0F;
    if ihl < 5 {
        return Err(ParseError::IpHeaderTooSmall(ihl));
    }

    let header_len = (ihl as usize) * 4;
    if data.len() < header_len {
        return Err(ParseError::PacketTooShort {
            expected: header_len,
            actual: data.len(),
        });
    }

    let dscp = (data[1] >> 2) & 0x3F;
    let ecn = data[1] & 0x03;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);

    // Parse flags and fragment offset
    let flags_and_offset = u16::from_be_bytes([data[6], data[7]]);
    let flags = ((flags_and_offset >> 13) & 0x07) as u8;
    let fragment_offset = flags_and_offset & 0x1FFF;

    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    // Validate checksum if requested (D32)
    if validate_checksum {
        let calculated = calculate_ip_checksum(&data[..header_len]);
        if calculated != 0 {
            // For a correct checksum, the sum including the checksum field should be 0
            return Err(ParseError::IpChecksumMismatch {
                expected: checksum,
                actual: calculated,
            });
        }
    }

    Ok(Ipv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip,
    })
}

/// Parse UDP header (8 bytes)
fn parse_udp(
    data: &[u8],
    ip_header: &Ipv4Header,
    _full_packet: &[u8],
    validate_checksum: bool,
) -> Result<UdpHeader, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::PacketTooShort {
            expected: 8,
            actual: data.len(),
        });
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    // Validate UDP checksum if requested (D32)
    // Note: UDP checksum is optional for IPv4 (checksum = 0 means no checksum)
    if validate_checksum && checksum != 0 {
        let calculated = calculate_udp_checksum(ip_header, &data[..length as usize]);
        if calculated != checksum {
            return Err(ParseError::UdpChecksumMismatch {
                expected: checksum,
                actual: calculated,
            });
        }
    }

    Ok(UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    })
}

/// Calculate IPv4 header checksum
///
/// The checksum is the 16-bit one's complement of the one's complement sum
/// of all 16-bit words in the header.
fn calculate_ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
        } else {
            // Odd byte - pad with zero
            sum += (data[i] as u32) << 8;
        }
    }

    // Add carries
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// Calculate UDP checksum (includes pseudo-header)
fn calculate_udp_checksum(ip_header: &Ipv4Header, udp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src IP
    for byte in ip_header.src_ip.octets() {
        sum += (byte as u32) << 8;
    }

    // Pseudo-header: dst IP
    for byte in ip_header.dst_ip.octets() {
        sum += (byte as u32) << 8;
    }

    // Pseudo-header: protocol (UDP = 17)
    sum += 17;

    // Pseudo-header: UDP length
    sum += udp_data.len() as u32;

    // UDP header + data
    for i in (0..udp_data.len()).step_by(2) {
        if i + 1 < udp_data.len() {
            let word = u16::from_be_bytes([udp_data[i], udp_data[i + 1]]);
            sum += word as u32;
        } else {
            sum += (udp_data[i] as u32) << 8;
        }
    }

    // Add carries
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid Ethernet/IPv4/UDP packet for testing
    fn create_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]); // Dst MAC (multicast)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        packet.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet.push(0x00); // DSCP 0, ECN 0
        packet.extend_from_slice(&[0x00, 0x2C]); // Total length: 44 bytes (20 IP + 8 UDP + 16 payload)
        packet.extend_from_slice(&[0x00, 0x01]); // Identification
        packet.extend_from_slice(&[0x00, 0x00]); // Flags: 0, Fragment offset: 0
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (will calculate)
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[239, 255, 0, 1]); // Dst IP (multicast)

        // Calculate and insert IP checksum
        let ip_start = 14;
        let ip_checksum = calculate_ip_checksum(&packet[ip_start..ip_start + 20]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // UDP header (8 bytes)
        packet.extend_from_slice(&[0x1F, 0x90]); // Src port: 8080
        packet.extend_from_slice(&[0x1F, 0x40]); // Dst port: 8000
        packet.extend_from_slice(&[0x00, 0x18]); // Length: 24 bytes (8 header + 16 payload)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum: 0 (optional for IPv4)

        // Payload (16 bytes)
        packet.extend_from_slice(b"Hello, multicast");

        packet
    }

    #[test]
    fn test_parse_valid_packet() {
        let packet = create_test_packet();
        let headers = parse_packet(&packet, false).expect("Should parse valid packet");

        // Verify Ethernet header
        assert_eq!(headers.ethernet.ether_type, 0x0800);
        assert_eq!(
            headers.ethernet.dst_mac,
            [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]
        );

        // Verify IPv4 header
        assert_eq!(headers.ipv4.version, 4);
        assert_eq!(headers.ipv4.protocol, 17);
        assert_eq!(headers.ipv4.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(headers.ipv4.dst_ip, Ipv4Addr::new(239, 255, 0, 1));
        assert!(!headers.ipv4.is_fragmented());

        // Verify UDP header
        assert_eq!(headers.udp.src_port, 8080);
        assert_eq!(headers.udp.dst_port, 8000);
        assert_eq!(headers.udp.length, 24);

        // Verify payload
        assert_eq!(headers.payload_offset, 14 + 20 + 8);
        assert_eq!(headers.payload_len, 16);
    }

    #[test]
    fn test_packet_too_short() {
        let packet = vec![0u8; 10]; // Too short for Ethernet header
        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::PacketTooShort { .. })));
    }

    #[test]
    fn test_invalid_ether_type() {
        let mut packet = create_test_packet();
        packet[12] = 0x86; // Change EtherType to 0x86DD (IPv6)
        packet[13] = 0xDD;

        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::InvalidEtherType(0x86DD))));
    }

    #[test]
    fn test_invalid_ip_version() {
        let mut packet = create_test_packet();
        packet[14] = 0x55; // Version 5, IHL 5

        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::InvalidIpVersion(5))));
    }

    #[test]
    fn test_invalid_protocol() {
        let mut packet = create_test_packet();
        packet[23] = 6; // Change protocol to TCP

        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::InvalidIpProtocol(6))));
    }

    #[test]
    fn test_fragmented_packet_mf_flag() {
        let mut packet = create_test_packet();
        // Set MF (More Fragments) flag
        packet[20] = 0x20; // Flags byte with MF set

        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::FragmentedPacket)));
    }

    #[test]
    fn test_fragmented_packet_offset() {
        let mut packet = create_test_packet();
        // Set fragment offset to non-zero
        packet[21] = 0x08; // Fragment offset = 1 (in 8-byte units)

        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::FragmentedPacket)));
    }

    #[test]
    fn test_matches_rule() {
        let packet = create_test_packet();
        let headers = parse_packet(&packet, false).unwrap();

        // Should match the correct group and port
        assert!(headers.matches(Ipv4Addr::new(239, 255, 0, 1), 8000));

        // Should not match wrong group
        assert!(!headers.matches(Ipv4Addr::new(239, 255, 0, 2), 8000));

        // Should not match wrong port
        assert!(!headers.matches(Ipv4Addr::new(239, 255, 0, 1), 9000));
    }

    #[test]
    fn test_buffer_size_for_payload() {
        use crate::worker::buffer_pool::BufferSize;

        let packet = create_test_packet();
        let headers = parse_packet(&packet, false).unwrap();

        // 16-byte payload should use Small buffer
        let size = BufferSize::for_payload(headers.payload_len);
        assert_eq!(size, Some(BufferSize::Small));
    }

    #[test]
    fn test_ip_checksum_calculation() {
        let packet = create_test_packet();
        let ip_start = 14;
        let ip_data = &packet[ip_start..ip_start + 20];

        // Checksum of a valid header (including checksum field) should be 0
        let checksum = calculate_ip_checksum(ip_data);
        assert_eq!(checksum, 0, "Valid IP checksum should result in 0");
    }
}
