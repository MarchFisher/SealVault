//! SealVault AEAD 算法模块。
//!
//! 统一管理可选算法与算法标识，具体实现见子模块。

pub mod aes_256_gcm;
pub mod xchacha20_poly1305;

/// 支持的 AEAD 算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    XChaCha20Poly1305,
    Aes256Gcm,
}

impl AeadAlgorithm {
    pub const XCHACHA20_POLY1305_ID: u8 = 1;
    pub const AES_256_GCM_ID: u8 = 2;

    pub fn to_u8(self) -> u8 {
        match self {
            Self::XChaCha20Poly1305 => Self::XCHACHA20_POLY1305_ID,
            Self::Aes256Gcm => Self::AES_256_GCM_ID,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            Self::XCHACHA20_POLY1305_ID => Some(Self::XChaCha20Poly1305),
            Self::AES_256_GCM_ID => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

// #[allow(clippy::unus)]
/// 默认算法：XChaCha20-Poly1305。
pub const _DEFAULT_AEAD_ALGORITHM: AeadAlgorithm = AeadAlgorithm::XChaCha20Poly1305;
