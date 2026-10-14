// SPDX-License-Identifier: Apache-2.0
//! Guest-only adapter to the unchanged private CDH API.
use zeroize::Zeroizing;
#[cfg(all(feature = "private-cdh", target_os = "linux"))]
pub mod private_cdh;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid measured storage KBS configuration")]
    Configuration,
    #[error("storage key authorization rejected")]
    Authorization,
    #[error("attested storage key retrieval failed")]
    Retrieval,
}
pub type Result<T> = std::result::Result<T, Error>;

/// No Debug, Clone or serialization; owned secret storage is wiped on drop.
pub struct KeyMaterial(Zeroizing<Vec<u8>>);
impl KeyMaterial {
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}
