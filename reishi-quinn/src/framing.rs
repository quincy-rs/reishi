//! VarInt-length-prefixed message framing for QUIC CRYPTO stream.
//!
//! Handshake messages are prefixed with a QUIC VarInt encoding their length.
//! Bytes may arrive fragmented across multiple `read_handshake` calls, so
//! the framer accumulates partial data until a complete message is available.
//! This includes handling fragmented VarInt length prefixes (which are 1–8
//! bytes depending on the encoded value).

use std::collections::VecDeque;

use quinn_proto::{VarInt, coding::Codec as _};

/// Error indicating that a handshake message could not be framed or parsed.
#[derive(Debug)]
pub struct InvalidHandshakeMessage;

/// Accumulates incoming bytes and yields complete framed handshake messages.
#[derive(Default)]
pub struct HandshakeMessageFramer {
    /// Buffer for a partial VarInt length prefix (QUIC VarInts are 1, 2, 4, or 8 bytes).
    varint_buf: [u8; 8],
    /// Number of valid bytes in `varint_buf`.
    varint_len: usize,
    /// In-progress message: (remaining_bytes, accumulated_data).
    message_in_progress: Option<(usize, Vec<u8>)>,
    /// Fully received messages ready for processing.
    messages_ready: VecDeque<Vec<u8>>,
}

/// Determine the expected byte length of a QUIC VarInt from its first byte.
///
/// QUIC VarInt encoding (RFC 9000 Section 16):
/// - `00xx_xxxx` → 1 byte  (values 0–63)
/// - `01xx_xxxx` → 2 bytes (values 0–16383)
/// - `10xx_xxxx` → 4 bytes (values 0–1073741823)
/// - `11xx_xxxx` → 8 bytes (values 0–4611686018427387903)
fn varint_len_from_first_byte(first: u8) -> usize {
    1 << (first >> 6)
}

impl HandshakeMessageFramer {
    /// Maximum length of a single handshake message.
    ///
    /// Limits resource consumption from unauthenticated peers.
    ///
    /// Standard Noise IK messages are small (~96–144 bytes + payload), so 4096
    /// is generous. When the `pq` feature is enabled, PQ IK Message 1 is ~4640
    /// bytes plus transport parameters, requiring a higher limit.
    #[cfg(not(feature = "pq"))]
    pub const MESSAGE_LEN_MAX: usize = 4096;

    /// Maximum length of a single handshake message (PQ mode).
    ///
    /// PQ IK Message 1 is ~4640 bytes + transport parameters payload, so 8192
    /// provides adequate headroom.
    #[cfg(feature = "pq")]
    pub const MESSAGE_LEN_MAX: usize = 8192;

    /// Maximum number of buffered ready messages before rejecting input.
    pub const MESSAGE_READY_MAX: usize = 8;

    /// Ingest incoming bytes from the CRYPTO stream.
    ///
    /// Returns `true` if at least one complete message is now available.
    pub fn ingest_bytes(&mut self, mut buffer: &[u8]) -> Result<bool, InvalidHandshakeMessage> {
        while !buffer.is_empty() {
            match &mut self.message_in_progress {
                None => {
                    // Reading the VarInt length prefix. We may need to accumulate
                    // bytes across calls if the VarInt spans multiple fragments.

                    // Grab the first byte if we haven't yet — it tells us how
                    // many total bytes the VarInt needs.
                    if self.varint_len == 0 {
                        self.varint_buf[0] = buffer[0];
                        self.varint_len = 1;
                        buffer = &buffer[1..];
                    }

                    let expected = varint_len_from_first_byte(self.varint_buf[0]);

                    // Accumulate up to `expected` bytes.
                    let need = expected - self.varint_len;
                    let take = need.min(buffer.len());
                    self.varint_buf[self.varint_len..self.varint_len + take]
                        .copy_from_slice(&buffer[..take]);
                    self.varint_len += take;
                    buffer = &buffer[take..];

                    if self.varint_len < expected {
                        // Not enough bytes yet — wait for the next call.
                        continue;
                    }

                    // Full VarInt available — decode it.
                    let mut varint_slice = &self.varint_buf[..expected];
                    let next_message_len: u64 = VarInt::decode(&mut varint_slice)
                        .map_err(|_| InvalidHandshakeMessage)?
                        .into();
                    self.varint_len = 0;

                    if next_message_len > Self::MESSAGE_LEN_MAX as u64
                        || self.messages_ready.len() >= Self::MESSAGE_READY_MAX
                    {
                        return Err(InvalidHandshakeMessage);
                    }
                    if next_message_len == 0 {
                        self.messages_ready.push_back(Vec::new());
                    } else {
                        let len = next_message_len as usize;
                        self.message_in_progress = Some((len, Vec::with_capacity(len)));
                    }
                }
                Some((bytes_remaining, message)) => {
                    let take_amt = (*bytes_remaining).min(buffer.len());
                    let (take, rem) = buffer.split_at(take_amt);
                    message.extend_from_slice(take);
                    *bytes_remaining -= take_amt;
                    if *bytes_remaining == 0 {
                        self.messages_ready
                            .push_back(self.message_in_progress.take().unwrap().1);
                    }
                    buffer = rem;
                }
            }
        }

        Ok(self.ready())
    }

    /// Whether at least one complete message is available.
    pub fn ready(&self) -> bool {
        !self.messages_ready.is_empty()
    }

    /// Pop the next complete message, if any.
    pub fn pop_message(&mut self) -> Option<Vec<u8>> {
        self.messages_ready.pop_front()
    }

    /// Write a length-prefixed frame into `buffer`.
    pub fn write_frame(
        buffer: &mut Vec<u8>,
        message: &[u8],
    ) -> Result<(), InvalidHandshakeMessage> {
        if message.len() > Self::MESSAGE_LEN_MAX {
            return Err(InvalidHandshakeMessage);
        }
        let len_var = VarInt::try_from(message.len()).map_err(|_| InvalidHandshakeMessage)?;
        len_var.encode(buffer);
        buffer.extend_from_slice(message);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_message() {
        let msg = b"hello noise";
        let mut buf = Vec::new();
        HandshakeMessageFramer::write_frame(&mut buf, msg).unwrap();

        let mut framer = HandshakeMessageFramer::default();
        assert!(!framer.ready());
        let has_data = framer.ingest_bytes(&buf).unwrap();
        assert!(has_data);
        assert!(framer.ready());

        let out = framer.pop_message().unwrap();
        assert_eq!(out, msg);
        assert!(!framer.ready());
    }

    #[test]
    fn round_trip_multiple_messages() {
        let msgs: &[&[u8]] = &[b"first", b"second", b"third"];
        let mut buf = Vec::new();
        for msg in msgs {
            HandshakeMessageFramer::write_frame(&mut buf, msg).unwrap();
        }

        let mut framer = HandshakeMessageFramer::default();
        framer.ingest_bytes(&buf).unwrap();

        for msg in msgs {
            let out = framer.pop_message().unwrap();
            assert_eq!(out, *msg);
        }
        assert!(framer.pop_message().is_none());
    }

    #[test]
    fn fragmented_delivery() {
        let msg = b"hello fragmented";
        let mut buf = Vec::new();
        HandshakeMessageFramer::write_frame(&mut buf, msg).unwrap();

        let mut framer = HandshakeMessageFramer::default();

        // Feed one byte at a time
        for (i, &byte) in buf.iter().enumerate() {
            let has_data = framer.ingest_bytes(&[byte]).unwrap();
            if i < buf.len() - 1 {
                assert!(!has_data, "should not be ready at byte {}", i);
            } else {
                assert!(has_data, "should be ready after last byte");
            }
        }

        let out = framer.pop_message().unwrap();
        assert_eq!(out, msg);
    }

    /// VarInt length prefixes that span multiple bytes (messages >= 64 bytes
    /// use a 2-byte VarInt) must survive fragmented delivery.
    #[test]
    fn fragmented_two_byte_varint() {
        // 96 bytes — typical Noise IK Message 1 size, uses a 2-byte VarInt prefix.
        let msg = vec![0xABu8; 96];
        let mut buf = Vec::new();
        HandshakeMessageFramer::write_frame(&mut buf, &msg).unwrap();

        // The VarInt for 96 is 2 bytes (0x40 | high, low). Verify the frame
        // is longer than 1 + 96 (i.e. the VarInt is multi-byte).
        assert!(buf.len() > 1 + 96, "expected 2-byte VarInt for length 96");

        // Deliver the first byte of the VarInt alone, then the rest.
        let mut framer = HandshakeMessageFramer::default();
        let ready = framer.ingest_bytes(&buf[..1]).unwrap();
        assert!(
            !ready,
            "should not be ready after just the first VarInt byte"
        );

        let ready = framer.ingest_bytes(&buf[1..]).unwrap();
        assert!(ready);

        let out = framer.pop_message().unwrap();
        assert_eq!(out, msg);
    }

    /// Byte-at-a-time delivery of a message with a 2-byte VarInt prefix.
    #[test]
    fn fragmented_two_byte_varint_byte_by_byte() {
        let msg = vec![0xCDu8; 200];
        let mut buf = Vec::new();
        HandshakeMessageFramer::write_frame(&mut buf, &msg).unwrap();

        let mut framer = HandshakeMessageFramer::default();
        for (i, &byte) in buf.iter().enumerate() {
            let has_data = framer.ingest_bytes(&[byte]).unwrap();
            if i < buf.len() - 1 {
                assert!(!has_data, "should not be ready at byte {i}");
            } else {
                assert!(has_data, "should be ready after last byte");
            }
        }

        let out = framer.pop_message().unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn empty_message() {
        let mut buf = Vec::new();
        HandshakeMessageFramer::write_frame(&mut buf, b"").unwrap();

        let mut framer = HandshakeMessageFramer::default();
        framer.ingest_bytes(&buf).unwrap();

        let out = framer.pop_message().unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn queue_limit_enforced() {
        let mut framer = HandshakeMessageFramer::default();
        let mut buf = Vec::new();
        for _ in 0..=HandshakeMessageFramer::MESSAGE_READY_MAX {
            HandshakeMessageFramer::write_frame(&mut buf, b"x").unwrap();
        }

        let result = framer.ingest_bytes(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn message_too_large() {
        let large = vec![0u8; HandshakeMessageFramer::MESSAGE_LEN_MAX + 1];
        let mut buf = Vec::new();
        let result = HandshakeMessageFramer::write_frame(&mut buf, &large);
        assert!(result.is_err());
    }
}
