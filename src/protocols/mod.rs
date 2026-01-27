// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Protocol implementations for PIM-SM, IGMP, and MSDP
//!
//! This module contains the state machines and packet handling for multicast
//! routing protocols that allow MCR to learn routes dynamically:
//!
//! - **IGMP (RFC 2236)**: Querier functionality and group membership tracking
//! - **PIM-SM (RFC 7761)**: Neighbor discovery, DR election, RP functionality
//! - **MSDP (RFC 3618)**: Inter-domain multicast source discovery
//!
//! ## Architecture
//!
//! Protocol state machines run in the Supervisor process (not workers):
//! - Centralized state management (neighbor tables, routing entries)
//! - Supervisor has tokio runtime for timer-driven operations
//! - Workers remain stateless relay engines
//! - Control plane packets are low-rate compared to data plane
//!
//! ## Packet Flow
//!
//! | Packet Type | Handler | Socket Type |
//! |-------------|---------|-------------|
//! | IGMP (proto 2) | Supervisor | Raw IP socket |
//! | PIM (proto 103) | Supervisor | Raw IP socket |
//! | MSDP (TCP 639) | Supervisor | TCP socket |
//! | Multicast data | Workers | AF_PACKET + AF_INET |

pub mod igmp;
pub mod msdp;
pub mod msdp_tcp;
pub mod pim;

use std::net::Ipv4Addr;
use std::time::Instant;

/// Events that can occur in protocol state machines
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    /// IGMP event
    Igmp(igmp::IgmpEvent),
    /// PIM event
    Pim(pim::PimEvent),
    /// MSDP event
    Msdp(msdp::MsdpEvent),
    /// Timer expired
    TimerExpired(TimerType),
}

/// Types of timers used by protocols
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimerType {
    /// IGMP general query timer (send periodic queries)
    IgmpGeneralQuery { interface: String },
    /// IGMP group-specific query timer
    IgmpGroupQuery { interface: String, group: Ipv4Addr },
    /// IGMP group membership expiry
    IgmpGroupExpiry { interface: String, group: Ipv4Addr },
    /// IGMP other querier present timer
    IgmpOtherQuerierPresent { interface: String },
    /// PIM hello timer
    PimHello { interface: String },
    /// PIM neighbor expiry
    PimNeighborExpiry {
        interface: String,
        neighbor: Ipv4Addr,
    },
    /// PIM Join/Prune timer
    PimJoinPrune { interface: String, group: Ipv4Addr },
    /// PIM (*,G) state expiry
    PimStarGExpiry { group: Ipv4Addr },
    /// PIM (S,G) state expiry
    PimSGExpiry { source: Ipv4Addr, group: Ipv4Addr },
    /// MSDP connect retry timer (attempt connection to peer)
    MsdpConnectRetry { peer: Ipv4Addr },
    /// MSDP keepalive timer (send keepalive to peer)
    MsdpKeepalive { peer: Ipv4Addr },
    /// MSDP hold timer (peer timeout)
    MsdpHold { peer: Ipv4Addr },
    /// MSDP SA cache entry expiry
    MsdpSaCacheExpiry {
        source: Ipv4Addr,
        group: Ipv4Addr,
        origin_rp: Ipv4Addr,
    },
}

/// Request to schedule a timer
#[derive(Debug, Clone)]
pub struct TimerRequest {
    /// Type of timer
    pub timer_type: TimerType,
    /// When the timer should fire
    pub fire_at: Instant,
    /// Whether this cancels any existing timer of the same type
    pub replace_existing: bool,
}

/// Common trait for protocol packet builders
pub trait PacketBuilder {
    /// Build a packet for transmission
    fn build(&self) -> Vec<u8>;

    /// Calculate checksum for the packet
    fn calculate_checksum(&self, data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..data.len()).step_by(2) {
            if i + 1 < data.len() {
                let word = u16::from_be_bytes([data[i], data[i + 1]]);
                sum = sum.wrapping_add(word as u32);
            } else {
                sum = sum.wrapping_add((data[i] as u32) << 8);
            }
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_type_equality() {
        let timer1 = TimerType::IgmpGeneralQuery {
            interface: "eth0".to_string(),
        };
        let timer2 = TimerType::IgmpGeneralQuery {
            interface: "eth0".to_string(),
        };
        let timer3 = TimerType::IgmpGeneralQuery {
            interface: "eth1".to_string(),
        };

        assert_eq!(timer1, timer2);
        assert_ne!(timer1, timer3);
    }
}
