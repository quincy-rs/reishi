use reishi_handshake::crypto::hash::HASH_LEN;
use reishi_handshake::{Error, Handshake, HandshakeAction, PublicKey};

#[cfg(feature = "pq")]
use reishi_handshake::{HybridHandshake, HybridPublicKey, PqHandshake, PqPublicKey};

pub(crate) enum RemoteIdentity {
    Classical(PublicKey),
    #[cfg(feature = "pq")]
    PostQuantum(Box<PqPublicKey>),
    #[cfg(feature = "pq")]
    Hybrid(Box<HybridPublicKey>),
}

pub(crate) enum ActiveHandshake {
    Classical(Box<Handshake>),
    #[cfg(feature = "pq")]
    PostQuantum(Box<PqHandshake>),
    #[cfg(feature = "pq")]
    Hybrid(Box<HybridHandshake>),
}

impl ActiveHandshake {
    pub fn next_action(&self) -> HandshakeAction {
        match self {
            Self::Classical(handshake) => handshake.next_action(),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.next_action(),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.next_action(),
        }
    }

    pub fn next_message_accepts_payload(&self) -> bool {
        match self {
            Self::Classical(handshake) => handshake.next_message_accepts_payload(),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.next_message_accepts_payload(),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.next_message_accepts_payload(),
        }
    }

    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Classical(handshake) => handshake.write_message(payload, output),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.write_message(payload, output),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.write_message(payload, output),
        }
    }

    pub fn read_message(&mut self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Classical(handshake) => handshake.read_message(message, output),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.read_message(message, output),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.read_message(message, output),
        }
    }

    pub fn next_message_overhead(&self) -> usize {
        match self {
            Self::Classical(handshake) => handshake.next_message_overhead(),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.next_message_overhead(),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.next_message_overhead(),
        }
    }

    pub fn get_ask(&self, label: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        match self {
            Self::Classical(handshake) => handshake.get_ask(label),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.get_ask(label),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.get_ask(label),
        }
    }

    pub fn handshake_hash(&self) -> Result<&[u8; HASH_LEN], Error> {
        match self {
            Self::Classical(handshake) => handshake.handshake_hash(),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.handshake_hash(),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.handshake_hash(),
        }
    }

    pub fn is_remote_authenticated(&self) -> bool {
        match self {
            Self::Classical(handshake) => handshake.is_remote_authenticated(),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake.is_remote_authenticated(),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake.is_remote_authenticated(),
        }
    }

    pub fn remote_identity(&self) -> Option<RemoteIdentity> {
        match self {
            Self::Classical(handshake) => handshake
                .remote_public_bytes()
                .map(PublicKey::from_bytes)
                .map(RemoteIdentity::Classical),
            #[cfg(feature = "pq")]
            Self::PostQuantum(handshake) => handshake
                .remote_public()
                .map(Box::new)
                .map(RemoteIdentity::PostQuantum),
            #[cfg(feature = "pq")]
            Self::Hybrid(handshake) => handshake
                .remote_public()
                .map(Box::new)
                .map(RemoteIdentity::Hybrid),
        }
    }
}
