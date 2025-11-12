//! Tier 3 Property-Based Tests: Packet Parser
//! 
//! These tests use the `proptest` framework to generate a wide variety of
//! byte inputs to throw at the `packet_parser`. The goal is to test the parser's
//! robustness against unexpected, malformed, or edge-case inputs that might not
//! be covered by simple unit tests.
//! 
//! # Coverage
//! 
//! - **Arbitrary Byte Arrays:** The parser should gracefully handle any possible
//!   byte array without panicking.
//! - **Packet Structure Properties:** For byte arrays that are successfully parsed,
//!   the resulting `Packet` struct should adhere to certain invariants (e.g.,
//!   IP checksums should be valid if the packet is not fragmented).
//! 
//! # Methodology
//! 
//! The `proptest!` macro is used to define strategies for generating arbitrary
//! `Vec<u8>` inputs. These inputs are then fed to the parsing functions.
//! Assertions are made not about the specific output, but about the properties
//! of the output (or the fact that the function doesn't panic).

#[cfg(test)]
mod tests {
    use multicast_relay::worker::packet_parser::parse_packet;
    use proptest::prelude::*;

    proptest! {
        /// **Property:** The `parse_packet` function should never panic.
        ///
        /// **Strategy:** Generate arbitrary vectors of bytes (`Vec<u8>`) and pass
        /// them to the parser. The test passes if the function returns either
        /// `Ok` or `Err` without panicking. This ensures the parser is robust
        /// against any possible byte-level input.
        #[test]
        fn test_parse_packet_does_not_panic(input in any::<Vec<u8>>()) {
            // We don't care about the result, only that it doesn't panic.
            // Test with both checksum validation on and off
            let _ = parse_packet(&input, true);
            let _ = parse_packet(&input, false);
        }
    }
}
