mod standard;

#[cfg(feature = "pq")]
pub mod pq;

pub use standard::{KeyPair, PublicKey, StaticSecret};

#[cfg(feature = "pq")]
pub use pq::{HYBRID_SECRET_LEN, PqKeyPair, PqPublicKey, PqStaticSecret};
