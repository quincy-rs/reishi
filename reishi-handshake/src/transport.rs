use zeroize::Zeroize;

use crate::cipher_state::CipherState;
use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::hash::HASH_LEN;
use crate::error::Error;

/// Post-handshake transport encryption state.
///
/// Contains two `CipherState`s: one for sending, one for receiving.
/// The assignment depends on which side (initiator/responder) this is:
/// - Initiator: c1 = send, c2 = recv
/// - Responder: c1 = recv, c2 = send
pub struct TransportState {
    send: CipherState,
    recv: CipherState,
    handshake_hash: [u8; HASH_LEN],
}

impl Drop for TransportState {
    fn drop(&mut self) {
        self.handshake_hash.zeroize();
    }
}

impl TransportState {
    pub(crate) fn new(
        handshake_hash: [u8; HASH_LEN],
        c1: CipherState,
        c2: CipherState,
        is_initiator: bool,
    ) -> Self {
        if is_initiator {
            Self {
                send: c1,
                recv: c2,
                handshake_hash,
            }
        } else {
            Self {
                send: c2,
                recv: c1,
                handshake_hash,
            }
        }
    }

    /// Encrypt a payload for sending to the peer.
    ///
    /// Returns the number of bytes written to `out` (payload + AEAD tag).
    /// `out` must be at least `payload.len() + 16` bytes.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.send.encrypt_with_ad(&[], payload, out)
    }

    /// Decrypt a message received from the peer.
    ///
    /// Returns the number of plaintext bytes written to `out`.
    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.recv.decrypt_with_ad(&[], message, out)
    }

    /// The final handshake hash — a channel binding value.
    ///
    /// Both sides will have the same value after a successful handshake.
    /// This can be used for additional authentication or channel binding.
    pub fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        &self.handshake_hash
    }

    /// The AEAD tag overhead per transport message.
    pub fn overhead(&self) -> usize {
        AEAD_TAG_LEN
    }

    /// Rekey the sending cipher (Noise spec Section 11.3).
    pub fn rekey_send(&mut self) -> Result<(), Error> {
        self.send.rekey()
    }

    /// Rekey the receiving cipher (Noise spec Section 11.3).
    pub fn rekey_recv(&mut self) -> Result<(), Error> {
        self.recv.rekey()
    }
}
