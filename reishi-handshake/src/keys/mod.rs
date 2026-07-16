mod standard;

#[cfg(feature = "pq")]
pub mod pq;

pub use standard::{KeyPair, PublicKey, StaticSecret};

#[cfg(feature = "pq")]
pub use pq::{
    EncapsulationKey, HybridKeyPair, HybridPublicKey, HybridStaticSecret, PqKeyPair, PqPublicKey,
    PqStaticSecret,
};
