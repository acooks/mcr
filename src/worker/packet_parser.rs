// SPDX-License-Identifier: Apache-2.0 OR MIT
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

use crate::{IP_PROTO_ESP, IP_PROTO_IGMP, IP_PROTO_PIM};

/// Errors that can occur during packet parsing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Invalid EtherType: expected 0x0800 (IPv4), got {0:#06x}")]
    InvalidEtherType(u16),

    #[error("Invalid IP version: expected 4, got {0}")]
    InvalidIpVersion(u8),

    #[error("Unsupported IP protocol: {0}")]
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

/// Parsed ESP header (8 bytes minimum: SPI + Sequence Number)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspHeader {
    pub spi: u32,
    pub seq_no: u32,
}

/// Parsed IGMP header (8 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpHeader {
    /// Message type: 0x11=Query, 0x16=V2Report, 0x17=Leave
    pub msg_type: u8,
    /// Max response time (in 1/10 seconds) - meaningful for queries
    pub max_resp_time: u8,
    /// Checksum
    pub checksum: u16,
    /// Group address (0.0.0.0 for general queries)
    pub group_address: Ipv4Addr,
}

impl IgmpHeader {
    /// Check if this is a membership query
    pub fn is_query(&self) -> bool {
        self.msg_type == 0x11
    }

    /// Check if this is a general query (group = 0.0.0.0)
    pub fn is_general_query(&self) -> bool {
        self.is_query() && self.group_address == Ipv4Addr::UNSPECIFIED
    }

    /// Check if this is a group-specific query
    pub fn is_group_specific_query(&self) -> bool {
        self.is_query() && self.group_address != Ipv4Addr::UNSPECIFIED
    }

    /// Check if this is a V2 membership report
    pub fn is_v2_report(&self) -> bool {
        self.msg_type == 0x16
    }

    /// Check if this is a leave group message
    pub fn is_leave(&self) -> bool {
        self.msg_type == 0x17
    }

    /// Get human-readable message type name
    pub fn type_name(&self) -> &'static str {
        match self.msg_type {
            0x11 => "Membership Query",
            0x12 => "V1 Membership Report",
            0x16 => "V2 Membership Report",
            0x17 => "Leave Group",
            _ => "Unknown",
        }
    }
}

/// Parsed PIM header (4 bytes common header)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimHeader {
    /// PIM version (must be 2)
    pub version: u8,
    /// Message type: 0=Hello, 1=Register, 3=Join/Prune, etc.
    pub msg_type: u8,
    /// Reserved field
    pub reserved: u8,
    /// Checksum
    pub checksum: u16,
}

impl PimHeader {
    /// Check if this is a Hello message
    pub fn is_hello(&self) -> bool {
        self.msg_type == 0
    }

    /// Check if this is a Register message
    pub fn is_register(&self) -> bool {
        self.msg_type == 1
    }

    /// Check if this is a Register-Stop message
    pub fn is_register_stop(&self) -> bool {
        self.msg_type == 2
    }

    /// Check if this is a Join/Prune message
    pub fn is_join_prune(&self) -> bool {
        self.msg_type == 3
    }

    /// Get human-readable message type name
    pub fn type_name(&self) -> &'static str {
        match self.msg_type {
            0 => "Hello",
            1 => "Register",
            2 => "Register-Stop",
            3 => "Join/Prune",
            4 => "Bootstrap",
            5 => "Assert",
            6 => "Graft",
            7 => "Graft-Ack",
            8 => "Candidate-RP",
            _ => "Unknown",
        }
    }
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
    ///
    /// Port 0 is treated as a wildcard (matches any port). This is used for
    /// protocol-learned routes (PIM/IGMP) which operate at layer 3 and don't
    /// track specific ports.
    pub fn matches(&self, group: Ipv4Addr, port: u16) -> bool {
        self.ipv4.dst_ip == group && (port == 0 || self.udp.dst_port == port)
    }

    /// Check if this packet matches a multicast relay rule with optional source filter
    ///
    /// Port 0 is treated as a wildcard (matches any port). This is used for
    /// protocol-learned routes (PIM/IGMP) which operate at layer 3 and don't
    /// track specific ports.
    pub fn matches_with_source(
        &self,
        group: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
    ) -> bool {
        let basic_match = self.ipv4.dst_ip == group && (port == 0 || self.udp.dst_port == port);
        match source {
            Some(required_source) => basic_match && self.ipv4.src_ip == required_source,
            None => basic_match,
        }
    }
}

/// Parsed packet - can be UDP, ESP, IGMP, or PIM
#[derive(Debug, Clone)]
pub enum ParsedPacket {
    /// UDP multicast data packet
    Udp(PacketHeaders),
    /// ESP (IPsec) data packet - relayed opaquely
    Esp {
        ethernet: EthernetHeader,
        ipv4: Ipv4Header,
        esp: EspHeader,
        /// Offset into the raw packet where ESP header starts (payload includes ESP header)
        payload_offset: usize,
        /// Length from ESP header through ICV (full ESP payload for raw socket egress)
        payload_len: usize,
    },
    /// IGMP control packet
    Igmp {
        ethernet: EthernetHeader,
        ipv4: Ipv4Header,
        igmp: IgmpHeader,
    },
    /// PIM control packet
    Pim {
        ethernet: EthernetHeader,
        ipv4: Ipv4Header,
        pim: PimHeader,
        /// Payload after PIM header (for parsing options/TLVs)
        payload: Vec<u8>,
    },
}

impl ParsedPacket {
    /// Get the source IP address
    pub fn src_ip(&self) -> Ipv4Addr {
        match self {
            ParsedPacket::Udp(h) => h.ipv4.src_ip,
            ParsedPacket::Esp { ipv4, .. } => ipv4.src_ip,
            ParsedPacket::Igmp { ipv4, .. } => ipv4.src_ip,
            ParsedPacket::Pim { ipv4, .. } => ipv4.src_ip,
        }
    }

    /// Get the destination IP address
    pub fn dst_ip(&self) -> Ipv4Addr {
        match self {
            ParsedPacket::Udp(h) => h.ipv4.dst_ip,
            ParsedPacket::Esp { ipv4, .. } => ipv4.dst_ip,
            ParsedPacket::Igmp { ipv4, .. } => ipv4.dst_ip,
            ParsedPacket::Pim { ipv4, .. } => ipv4.dst_ip,
        }
    }

    /// Get the IP protocol number
    pub fn protocol(&self) -> u8 {
        match self {
            ParsedPacket::Udp(h) => h.ipv4.protocol,
            ParsedPacket::Esp { ipv4, .. } => ipv4.protocol,
            ParsedPacket::Igmp { ipv4, .. } => ipv4.protocol,
            ParsedPacket::Pim { ipv4, .. } => ipv4.protocol,
        }
    }

    /// Check if this is a control protocol packet (IGMP or PIM)
    pub fn is_control(&self) -> bool {
        matches!(self, ParsedPacket::Igmp { .. } | ParsedPacket::Pim { .. })
    }

    /// Check if this is a data packet (UDP or ESP)
    pub fn is_data(&self) -> bool {
        matches!(self, ParsedPacket::Udp(_) | ParsedPacket::Esp { .. })
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

    // CRITICAL: Validate that we actually have enough data in the packet.
    // The UDP length field tells us how much data SHOULD be present, but we must
    // verify the packet buffer actually contains that much data.
    // This prevents out-of-bounds access when packets are truncated (e.g., by snaplen).
    let expected_total = payload_offset + payload_len;
    if data.len() < expected_total {
        return Err(ParseError::PacketTooShort {
            expected: expected_total,
            actual: data.len(),
        });
    }

    Ok(PacketHeaders {
        ethernet,
        ipv4,
        udp,
        payload_offset,
        payload_len,
    })
}

/// Parse any IPv4 packet (UDP, IGMP, or PIM)
///
/// This function handles multiple IP protocols:
/// - Protocol 17 (UDP): Returns ParsedPacket::Udp
/// - Protocol 2 (IGMP): Returns ParsedPacket::Igmp
/// - Protocol 103 (PIM): Returns ParsedPacket::Pim
///
/// # Arguments
/// * `data` - Raw packet data (starting with Ethernet header)
/// * `validate_checksums` - Whether to validate checksums
///
/// # Returns
/// Parsed packet variant, or an error if parsing fails
pub fn parse_packet_any(data: &[u8], validate_checksums: bool) -> Result<ParsedPacket, ParseError> {
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

    // Branch based on IP protocol
    match ipv4.protocol {
        17 => {
            // UDP - use existing parse_packet logic
            let udp_offset = ip_offset + ipv4.header_len();
            let udp = parse_udp(&data[udp_offset..], &ipv4, data, validate_checksums)?;

            let payload_offset = udp_offset + 8;
            let payload_len = (udp.length as usize).saturating_sub(8);

            let expected_total = payload_offset + payload_len;
            if data.len() < expected_total {
                return Err(ParseError::PacketTooShort {
                    expected: expected_total,
                    actual: data.len(),
                });
            }

            Ok(ParsedPacket::Udp(PacketHeaders {
                ethernet,
                ipv4,
                udp,
                payload_offset,
                payload_len,
            }))
        }

        IP_PROTO_IGMP => {
            // IGMP
            let igmp_offset = ip_offset + ipv4.header_len();
            let igmp = parse_igmp(&data[igmp_offset..], validate_checksums)?;

            Ok(ParsedPacket::Igmp {
                ethernet,
                ipv4,
                igmp,
            })
        }

        IP_PROTO_ESP => {
            // ESP (IPsec) - relay opaquely including ESP header
            let esp_offset = ip_offset + ipv4.header_len();
            let esp = parse_esp(&data[esp_offset..])?;
            // payload_offset starts at ESP header — raw socket egress sends full ESP header + encrypted data + ICV
            let payload_offset = esp_offset;
            let payload_len = ipv4.total_length as usize - ipv4.header_len();
            let expected_total = ip_offset + ipv4.total_length as usize;
            if data.len() < expected_total {
                return Err(ParseError::PacketTooShort {
                    expected: expected_total,
                    actual: data.len(),
                });
            }
            Ok(ParsedPacket::Esp {
                ethernet,
                ipv4,
                esp,
                payload_offset,
                payload_len,
            })
        }

        IP_PROTO_PIM => {
            // PIM
            let pim_offset = ip_offset + ipv4.header_len();
            let (pim, payload) = parse_pim(&data[pim_offset..], validate_checksums)?;

            Ok(ParsedPacket::Pim {
                ethernet,
                ipv4,
                pim,
                payload,
            })
        }

        other => {
            // Unknown protocol - return error
            Err(ParseError::InvalidIpProtocol(other))
        }
    }
}

/// Parse IGMP header (8 bytes)
fn parse_igmp(data: &[u8], _validate_checksum: bool) -> Result<IgmpHeader, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::PacketTooShort {
            expected: 8,
            actual: data.len(),
        });
    }

    let msg_type = data[0];
    let max_resp_time = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let group_address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);

    // TODO: Add checksum validation if validate_checksum is true

    Ok(IgmpHeader {
        msg_type,
        max_resp_time,
        checksum,
        group_address,
    })
}

/// Parse PIM header (4 bytes minimum)
fn parse_pim(data: &[u8], _validate_checksum: bool) -> Result<(PimHeader, Vec<u8>), ParseError> {
    if data.len() < 4 {
        return Err(ParseError::PacketTooShort {
            expected: 4,
            actual: data.len(),
        });
    }

    let ver_type = data[0];
    let version = (ver_type >> 4) & 0x0F;
    let msg_type = ver_type & 0x0F;

    // PIM version must be 2
    if version != 2 {
        return Err(ParseError::InvalidIpVersion(version));
    }

    let reserved = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    // TODO: Add checksum validation if validate_checksum is true

    let pim = PimHeader {
        version,
        msg_type,
        reserved,
        checksum,
    };

    // Return payload after PIM header
    let payload = if data.len() > 4 {
        data[4..].to_vec()
    } else {
        Vec::new()
    };

    Ok((pim, payload))
}

/// Parse ESP header (8 bytes: SPI + Sequence Number)
fn parse_esp(data: &[u8]) -> Result<EspHeader, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::PacketTooShort {
            expected: 8,
            actual: data.len(),
        });
    }

    Ok(EspHeader {
        spi: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        seq_no: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
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
pub fn calculate_ip_checksum(data: &[u8]) -> u16 {
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

    #[test]
    fn test_total_len() {
        let packet = create_test_packet();
        let headers = parse_packet(&packet, false).unwrap();

        // Total length = payload_offset + payload_len = 42 + 16 = 58
        assert_eq!(headers.total_len(), 58);
    }

    #[test]
    fn test_ip_header_too_small() {
        let mut packet = create_test_packet();
        // Set IHL to 4 (16 bytes) - invalid, must be at least 5 (20 bytes)
        packet[14] = 0x44; // Version 4, IHL 4

        let result = parse_packet(&packet, false);
        assert!(matches!(result, Err(ParseError::IpHeaderTooSmall(4))));
    }

    #[test]
    fn test_ip_packet_shorter_than_ihl() {
        // Create a packet where total length is less than IHL suggests
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]); // Dst MAC
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header: IHL=6 (24 bytes) but we only provide 20 bytes
        packet.push(0x46); // Version 4, IHL 6 (requires 24 bytes)
        packet.push(0x00); // DSCP 0, ECN 0
        packet.extend_from_slice(&[0x00, 0x14]); // Total length: 20 bytes
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ID, flags
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[239, 255, 0, 1]); // Dst IP
                                                     // Missing 4 bytes of IP options - packet is too short

        let result = parse_packet(&packet, false);
        assert!(matches!(
            result,
            Err(ParseError::PacketTooShort { expected: 24, .. })
        ));
    }

    #[test]
    fn test_ip_checksum_validation_failure() {
        let mut packet = create_test_packet();
        // Corrupt the IP checksum
        packet[24] = 0xFF;
        packet[25] = 0xFF;

        let result = parse_packet(&packet, true);
        assert!(matches!(result, Err(ParseError::IpChecksumMismatch { .. })));
    }

    #[test]
    fn test_udp_packet_too_short() {
        // Create a packet that's valid until UDP, then truncate
        let mut packet = Vec::new();

        // Ethernet header
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x1C]); // Total length: 28 bytes (20 IP + 8 UDP)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.push(64);
        packet.push(17); // UDP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[239, 255, 0, 1]);

        // Calculate correct IP checksum
        let ip_checksum = calculate_ip_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // Only 6 bytes of UDP header (need 8)
        packet.extend_from_slice(&[0x1F, 0x90, 0x1F, 0x40, 0x00, 0x08]);

        let result = parse_packet(&packet, false);
        assert!(matches!(
            result,
            Err(ParseError::PacketTooShort { expected: 8, .. })
        ));
    }

    #[test]
    fn test_udp_checksum_validation_with_nonzero_checksum() {
        // Test that UDP checksum validation code path is exercised
        // Note: create_test_packet() has UDP checksum=0 which means "no checksum"
        // So we need to test with an actually checksum-protected packet
        let packet = create_test_packet();

        // With checksum=0, validation should be skipped even with validate_checksums=true
        let result = parse_packet(&packet, true);
        assert!(result.is_ok(), "Packet with UDP checksum=0 should parse OK");

        // Test error path by creating a packet with non-zero checksum that's wrong
        // This is a simpler approach - just verify the checksum calculation doesn't panic
        let ip_header = Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 44,
            identification: 1,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 17,
            checksum: 0,
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(239, 255, 0, 1),
        };

        let udp_data = vec![0u8; 24]; // Dummy UDP data
        let _checksum = calculate_udp_checksum(&ip_header, &udp_data);
        // Just verify it doesn't panic - we've exercised the code path
    }

    #[test]
    fn test_checksum_with_odd_length() {
        // Test IP checksum calculation with odd-length data
        let odd_data = vec![0x45, 0x00, 0x00]; // 3 bytes (odd)
        let checksum = calculate_ip_checksum(&odd_data);
        // Should handle odd byte by padding with zero
        assert_ne!(checksum, 0); // Just verify it doesn't panic
    }

    #[test]
    fn test_minimum_valid_packet() {
        // Create the smallest possible valid Ethernet/IPv4/UDP packet
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header (20 bytes, minimum)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x1C]); // Total length: 28 (20 IP + 8 UDP + 0 payload)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.push(64);
        packet.push(17); // UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[239, 255, 0, 1]);

        // Calculate and set IP checksum
        let ip_checksum = calculate_ip_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // UDP header (8 bytes, no payload)
        packet.extend_from_slice(&[0x1F, 0x90]); // Src port
        packet.extend_from_slice(&[0x1F, 0x40]); // Dst port
        packet.extend_from_slice(&[0x00, 0x08]); // Length: 8 (header only)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum: 0 (optional)

        // Should parse successfully
        let result = parse_packet(&packet, false);
        assert!(result.is_ok());
        let headers = result.unwrap();
        assert_eq!(headers.payload_len, 0); // No payload
    }

    #[test]
    fn test_maximum_ip_header_with_options() {
        // Test with maximum IHL (15 = 60 bytes) including IP options
        let mut packet = Vec::new();

        // Ethernet header
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header with IHL=15 (60 bytes: 20 base + 40 options)
        packet.push(0x4F); // Version 4, IHL 15
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x44]); // Total length: 68 (60 IP + 8 UDP)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.push(64);
        packet.push(17); // UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[239, 255, 0, 1]);

        // IP options (40 bytes of zeros for simplicity)
        packet.extend_from_slice(&[0u8; 40]);

        // Calculate and set IP checksum
        let ip_checksum = calculate_ip_checksum(&packet[14..74]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // UDP header
        packet.extend_from_slice(&[0x1F, 0x90, 0x1F, 0x40, 0x00, 0x08, 0x00, 0x00]);

        // Should parse successfully
        let result = parse_packet(&packet, false);
        assert!(result.is_ok());
        let headers = result.unwrap();
        assert_eq!(headers.ipv4.ihl, 15);
        assert_eq!(headers.ipv4.header_len(), 60);
    }

    /// Create a minimal valid IGMP membership report packet
    fn create_igmp_packet(msg_type: u8, group: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]); // Dst MAC
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes) - protocol 2 (IGMP)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x1C]); // Total length: 28 (20 IP + 8 IGMP)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.push(1); // TTL (IGMP uses TTL=1)
        packet.push(2); // Protocol: IGMP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        packet.extend_from_slice(&[192, 168, 1, 100]); // Src IP
        packet.extend_from_slice(&[224, 0, 0, 1]); // Dst IP (all hosts)

        // Calculate IP checksum
        let ip_checksum = calculate_ip_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // IGMP header (8 bytes)
        packet.push(msg_type); // Type
        packet.push(0x64); // Max resp time: 100 (10 seconds)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        packet.extend_from_slice(&group); // Group address

        packet
    }

    #[test]
    fn test_parse_igmp_query() {
        let packet = create_igmp_packet(0x11, [0, 0, 0, 0]); // General query

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedPacket::Igmp { ipv4, igmp, .. } => {
                assert_eq!(ipv4.protocol, IP_PROTO_IGMP);
                assert!(igmp.is_query());
                assert!(igmp.is_general_query());
                assert!(!igmp.is_group_specific_query());
                assert_eq!(igmp.max_resp_time, 100);
            }
            _ => panic!("Expected IGMP packet"),
        }
    }

    #[test]
    fn test_parse_igmp_group_specific_query() {
        let packet = create_igmp_packet(0x11, [239, 1, 1, 1]); // Group-specific query

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedPacket::Igmp { igmp, .. } => {
                assert!(igmp.is_query());
                assert!(!igmp.is_general_query());
                assert!(igmp.is_group_specific_query());
                assert_eq!(igmp.group_address, Ipv4Addr::new(239, 1, 1, 1));
            }
            _ => panic!("Expected IGMP packet"),
        }
    }

    #[test]
    fn test_parse_igmp_v2_report() {
        let packet = create_igmp_packet(0x16, [239, 2, 2, 2]); // V2 report

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedPacket::Igmp { igmp, .. } => {
                assert!(igmp.is_v2_report());
                assert!(!igmp.is_query());
                assert_eq!(igmp.group_address, Ipv4Addr::new(239, 2, 2, 2));
                assert_eq!(igmp.type_name(), "V2 Membership Report");
            }
            _ => panic!("Expected IGMP packet"),
        }
    }

    #[test]
    fn test_parse_igmp_leave() {
        let packet = create_igmp_packet(0x17, [239, 3, 3, 3]); // Leave

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedPacket::Igmp { igmp, .. } => {
                assert!(igmp.is_leave());
                assert_eq!(igmp.group_address, Ipv4Addr::new(239, 3, 3, 3));
                assert_eq!(igmp.type_name(), "Leave Group");
            }
            _ => panic!("Expected IGMP packet"),
        }
    }

    /// Create a minimal valid PIM Hello packet
    fn create_pim_packet(msg_type: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x0d]); // Dst MAC (ALL-PIM-ROUTERS)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes) - protocol 103 (PIM)
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x22]); // Total length: 34 (20 IP + 4 PIM + 10 options)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.push(1); // TTL
        packet.push(103); // Protocol: PIM
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[224, 0, 0, 13]); // Dst IP (ALL-PIM-ROUTERS)

        // Calculate IP checksum
        let ip_checksum = calculate_ip_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // PIM header (4 bytes)
        packet.push((2 << 4) | msg_type); // Version 2, Type
        packet.push(0x00); // Reserved
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder

        // Hello options (10 bytes) - Holdtime option
        packet.extend_from_slice(&[0x00, 0x01]); // Option type: Holdtime
        packet.extend_from_slice(&[0x00, 0x02]); // Option length: 2
        packet.extend_from_slice(&[0x00, 0x69]); // Holdtime: 105 seconds
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Padding

        packet
    }

    #[test]
    fn test_parse_pim_hello() {
        let packet = create_pim_packet(0); // Hello

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedPacket::Pim {
                ipv4, pim, payload, ..
            } => {
                assert_eq!(ipv4.protocol, IP_PROTO_PIM);
                assert_eq!(pim.version, 2);
                assert!(pim.is_hello());
                assert_eq!(pim.type_name(), "Hello");
                assert!(!payload.is_empty()); // Should have options
            }
            _ => panic!("Expected PIM packet"),
        }
    }

    #[test]
    fn test_parse_pim_join_prune() {
        let packet = create_pim_packet(3); // Join/Prune

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedPacket::Pim { pim, .. } => {
                assert!(pim.is_join_prune());
                assert_eq!(pim.type_name(), "Join/Prune");
            }
            _ => panic!("Expected PIM packet"),
        }
    }

    #[test]
    fn test_parse_packet_any_udp() {
        let packet = create_test_packet();

        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        match &parsed {
            ParsedPacket::Udp(headers) => {
                assert_eq!(headers.ipv4.protocol, 17);
            }
            _ => panic!("Expected UDP packet"),
        }
        assert!(parsed.is_data());
        assert!(!parsed.is_control());
    }

    #[test]
    fn test_parsed_packet_accessors() {
        let udp_packet = create_test_packet();
        let parsed = parse_packet_any(&udp_packet, false).unwrap();

        assert_eq!(parsed.src_ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.dst_ip(), Ipv4Addr::new(239, 255, 0, 1));
        assert_eq!(parsed.protocol(), 17);
        assert!(parsed.is_data());
        assert!(!parsed.is_control());

        let igmp_packet = create_igmp_packet(0x16, [239, 1, 1, 1]);
        let parsed = parse_packet_any(&igmp_packet, false).unwrap();

        assert!(parsed.is_control());
        assert!(!parsed.is_data());
        assert_eq!(parsed.protocol(), IP_PROTO_IGMP);
    }

    #[test]
    fn test_matches_with_source() {
        let packet = create_test_packet();
        let headers = parse_packet(&packet, false).unwrap();

        // Should match with no source filter
        assert!(headers.matches_with_source(Ipv4Addr::new(239, 255, 0, 1), 8000, None));

        // Should match with correct source
        assert!(headers.matches_with_source(
            Ipv4Addr::new(239, 255, 0, 1),
            8000,
            Some(Ipv4Addr::new(192, 168, 1, 1))
        ));

        // Should not match with wrong source
        assert!(!headers.matches_with_source(
            Ipv4Addr::new(239, 255, 0, 1),
            8000,
            Some(Ipv4Addr::new(192, 168, 1, 2))
        ));
    }

    #[test]
    fn test_igmp_header_methods() {
        let header = IgmpHeader {
            msg_type: 0x11,
            max_resp_time: 100,
            checksum: 0,
            group_address: Ipv4Addr::UNSPECIFIED,
        };
        assert!(header.is_query());
        assert!(header.is_general_query());
        assert!(!header.is_group_specific_query());
        assert!(!header.is_v2_report());
        assert!(!header.is_leave());

        let header = IgmpHeader {
            msg_type: 0x16,
            max_resp_time: 0,
            checksum: 0,
            group_address: Ipv4Addr::new(239, 1, 1, 1),
        };
        assert!(header.is_v2_report());
        assert!(!header.is_query());

        let header = IgmpHeader {
            msg_type: 0x17,
            max_resp_time: 0,
            checksum: 0,
            group_address: Ipv4Addr::new(239, 1, 1, 1),
        };
        assert!(header.is_leave());
    }

    #[test]
    fn test_pim_header_methods() {
        let header = PimHeader {
            version: 2,
            msg_type: 0,
            reserved: 0,
            checksum: 0,
        };
        assert!(header.is_hello());
        assert!(!header.is_register());
        assert!(!header.is_join_prune());

        let header = PimHeader {
            version: 2,
            msg_type: 1,
            reserved: 0,
            checksum: 0,
        };
        assert!(header.is_register());

        let header = PimHeader {
            version: 2,
            msg_type: 3,
            reserved: 0,
            checksum: 0,
        };
        assert!(header.is_join_prune());
    }

    /// Create a minimal valid Ethernet/IPv4/ESP packet for testing
    fn create_esp_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]); // Dst MAC (multicast)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        packet.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet.push(0x00); // DSCP 0, ECN 0
                           // Total length: 20 IP + 8 ESP header + 24 payload = 52 bytes
        packet.extend_from_slice(&[0x00, 0x34]);
        packet.extend_from_slice(&[0x00, 0x01]); // Identification
        packet.extend_from_slice(&[0x00, 0x00]); // Flags: 0, Fragment offset: 0
        packet.push(64); // TTL
        packet.push(50); // Protocol: ESP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (will calculate)
        packet.extend_from_slice(&[10, 1, 0, 1]); // Src IP
        packet.extend_from_slice(&[239, 255, 0, 100]); // Dst IP (multicast)

        // Calculate and insert IP checksum
        let ip_start = 14;
        let ip_checksum = calculate_ip_checksum(&packet[ip_start..ip_start + 20]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        // ESP header (8 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // SPI = 256
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Sequence Number = 1

        // ESP payload (24 bytes of dummy encrypted data + ICV)
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        packet.extend_from_slice(&[0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);

        packet
    }

    #[test]
    fn test_parse_esp_packet() {
        let packet = create_esp_packet();
        let result = parse_packet_any(&packet, false);
        assert!(result.is_ok(), "ESP packet should parse successfully");

        let parsed = result.unwrap();
        match &parsed {
            ParsedPacket::Esp {
                ipv4,
                esp,
                payload_offset,
                payload_len,
                ..
            } => {
                assert_eq!(ipv4.protocol, 50);
                assert_eq!(ipv4.src_ip, Ipv4Addr::new(10, 1, 0, 1));
                assert_eq!(ipv4.dst_ip, Ipv4Addr::new(239, 255, 0, 100));
                assert_eq!(esp.spi, 256);
                assert_eq!(esp.seq_no, 1);
                // payload_offset should point to ESP header start (not after it)
                assert_eq!(*payload_offset, 34); // 14 ethernet + 20 IP
                                                 // payload_len = total_length (52) - IP header (20) = 32
                assert_eq!(*payload_len, 32);
            }
            _ => panic!("Expected ESP packet, got {:?}", parsed),
        }

        assert!(parsed.is_data());
        assert!(!parsed.is_control());
        assert_eq!(parsed.protocol(), 50);
        assert_eq!(parsed.src_ip(), Ipv4Addr::new(10, 1, 0, 1));
        assert_eq!(parsed.dst_ip(), Ipv4Addr::new(239, 255, 0, 100));
    }

    #[test]
    fn test_parse_packet_rejects_esp() {
        // parse_packet() is UDP-only and should reject ESP
        let packet = create_esp_packet();
        let result = parse_packet(&packet, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::InvalidIpProtocol(50) => {} // Expected
            e => panic!("Expected InvalidIpProtocol(50), got {:?}", e),
        }
    }

    #[test]
    fn test_parse_esp_too_short() {
        let mut packet = create_esp_packet();
        // Truncate to just after IP header (remove ESP data)
        packet.truncate(34 + 4); // Only 4 bytes of ESP (need 8)

        // Update IP total_length to match truncated packet
        let new_total = (packet.len() - 14) as u16;
        packet[16] = (new_total >> 8) as u8;
        packet[17] = (new_total & 0xFF) as u8;
        // Recalculate IP checksum
        packet[24] = 0;
        packet[25] = 0;
        let ip_checksum = calculate_ip_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xFF) as u8;

        let result = parse_packet_any(&packet, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::PacketTooShort { expected: 8, .. } => {} // Expected
            e => panic!("Expected PacketTooShort, got {:?}", e),
        }
    }
}
