//! Command reader for parsing length-delimited JSON commands from io_uring
//!
//! This module provides a stateful parser for the length-delimited codec used
//! by the supervisor to send commands to workers. It handles partial reads and
//! buffers data until complete frames are available.

use crate::RelayCommand;
use anyhow::{Context, Result};

/// Helper for parsing length-delimited JSON commands from a stream
///
/// The wire format is:
/// - 4 bytes: frame length (u32, big-endian)
/// - N bytes: JSON payload
///
/// This struct maintains internal buffering to handle partial reads from io_uring.
pub struct CommandReader {
    buffer: Vec<u8>,
    pending_frame_len: Option<usize>,
}

impl CommandReader {
    /// Create a new CommandReader with default buffer capacity
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            pending_frame_len: None,
        }
    }

    /// Process newly read bytes and return any complete commands
    ///
    /// This method should be called with the bytes read from io_uring.
    /// It appends them to the internal buffer and attempts to parse
    /// complete frames. Any complete commands are returned.
    ///
    /// # Arguments
    /// * `new_bytes` - Bytes read from the command stream
    ///
    /// # Returns
    /// A vector of successfully parsed commands (may be empty if no complete frames)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Frame length is invalid or too large
    /// - JSON deserialization fails
    pub fn process_bytes(&mut self, new_bytes: &[u8]) -> Result<Vec<RelayCommand>> {
        self.buffer.extend_from_slice(new_bytes);
        let mut commands = Vec::new();

        loop {
            // Parse frame length (4 bytes, big-endian)
            if self.pending_frame_len.is_none() {
                if self.buffer.len() < 4 {
                    break; // Need more data for frame length
                }

                let len_bytes: [u8; 4] = self.buffer[0..4]
                    .try_into()
                    .context("Failed to read frame length")?;
                let frame_len = u32::from_be_bytes(len_bytes) as usize;

                // Sanity check: reject unreasonably large frames (1MB limit)
                if frame_len > 1_048_576 {
                    anyhow::bail!("Frame length too large: {} bytes", frame_len);
                }

                self.pending_frame_len = Some(frame_len);
            }

            // Parse frame data
            if let Some(frame_len) = self.pending_frame_len {
                if self.buffer.len() >= 4 + frame_len {
                    // Full frame available
                    let frame = &self.buffer[4..4 + frame_len];
                    let cmd: RelayCommand = serde_json::from_slice(frame)
                        .context("Failed to deserialize RelayCommand")?;
                    commands.push(cmd);

                    // Remove frame from buffer
                    self.buffer.drain(0..4 + frame_len);
                    self.pending_frame_len = None;
                } else {
                    break; // Need more data for frame payload
                }
            }
        }

        Ok(commands)
    }

    /// Get the current buffer size (for debugging/monitoring)
    #[allow(dead_code)]
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Get the pending frame length if we're waiting for more data
    #[allow(dead_code)]
    pub fn pending_frame_len(&self) -> Option<usize> {
        self.pending_frame_len
    }
}

impl Default for CommandReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForwardingRule, RelayCommand};
    use std::net::Ipv4Addr;

    fn create_frame(cmd: &RelayCommand) -> Vec<u8> {
        let json = serde_json::to_vec(cmd).unwrap();
        let len = json.len() as u32;
        let mut frame = len.to_be_bytes().to_vec();
        frame.extend(json);
        frame
    }

    #[test]
    fn test_single_complete_frame() {
        let mut reader = CommandReader::new();
        let cmd = RelayCommand::Shutdown;
        let frame = create_frame(&cmd);

        let commands = reader.process_bytes(&frame).unwrap();
        assert_eq!(commands.len(), 1);
        assert!(matches!(commands[0], RelayCommand::Shutdown));
    }

    #[test]
    fn test_partial_frame_length() {
        let mut reader = CommandReader::new();
        let cmd = RelayCommand::Shutdown;
        let frame = create_frame(&cmd);

        // Send only first 2 bytes of length
        let commands = reader.process_bytes(&frame[0..2]).unwrap();
        assert_eq!(commands.len(), 0);

        // Send rest
        let commands = reader.process_bytes(&frame[2..]).unwrap();
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn test_partial_frame_data() {
        let mut reader = CommandReader::new();
        let cmd = RelayCommand::Shutdown;
        let frame = create_frame(&cmd);

        // Send length + half of data
        let split_point = 4 + (frame.len() - 4) / 2;
        let commands = reader.process_bytes(&frame[0..split_point]).unwrap();
        assert_eq!(commands.len(), 0);

        // Send rest of data
        let commands = reader.process_bytes(&frame[split_point..]).unwrap();
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn test_multiple_frames_in_one_read() {
        use crate::OutputDestination;

        let mut reader = CommandReader::new();
        let cmd1 = RelayCommand::Shutdown;
        let cmd2 = RelayCommand::AddRule(ForwardingRule {
            rule_id: "test_rule".to_string(),
            input_interface: "eth0".to_string(),
            input_group: Ipv4Addr::new(239, 1, 1, 1),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: Ipv4Addr::new(239, 2, 2, 2),
                port: 6000,
                interface: "eth1".to_string(),
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        });

        let mut data = create_frame(&cmd1);
        data.extend(create_frame(&cmd2));

        let commands = reader.process_bytes(&data).unwrap();
        assert_eq!(commands.len(), 2);
        assert!(matches!(commands[0], RelayCommand::Shutdown));
        assert!(matches!(commands[1], RelayCommand::AddRule(_)));
    }

    #[test]
    fn test_invalid_json() {
        let mut reader = CommandReader::new();
        let mut frame = vec![0, 0, 0, 5]; // length = 5
        frame.extend(b"notjson"); // But this is 7 bytes, so we'll get 5

        let frame = &frame[0..9]; // length header + 5 bytes
        let result = reader.process_bytes(frame);
        assert!(result.is_err());
    }

    #[test]
    fn test_frame_too_large() {
        let mut reader = CommandReader::new();
        let frame = vec![0xFF, 0xFF, 0xFF, 0xFF]; // 4GB frame length

        let result = reader.process_bytes(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
