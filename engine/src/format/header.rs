//! SealVault Header 实现
//!
//! 本模块定义并实现 SealVault 文件格式中的 Header 部分。

use std::io::{Read, Write};

/// SealVault 文件魔数（ASCII）
pub const MAGIC: &[u8; 8] = b"SVLTv1\0\0";

/// 兼容读取的旧版本号（默认 XChaCha20-Poly1305）
pub const VERSION_V1: u8 = 1;
/// 当前版本号（携带算法字段）
pub const VERSION_V2: u8 = 2;

/// 当前加密默认版本
pub const VERSION: u8 = VERSION_V2;

/// KDF 使用的 salt 长度（字节）
pub const SALT_SIZE: usize = 16;

/// Header 中 base nonce 存储长度（字节）
///
/// - XChaCha20-Poly1305 实际使用 24 字节
/// - AES-256-GCM 实际使用前 12 字节
pub const BASE_NONCE_SIZE: usize = 24;

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

/// 默认算法：XChaCha20-Poly1305。
pub const DEFAULT_AEAD_ALGORITHM: AeadAlgorithm = AeadAlgorithm::XChaCha20Poly1305;

/// SealVault v1 Header 固定大小
///
/// 8  (magic)
/// 1  (version)
/// 16 (salt)
/// 24 (base_nonce)
/// 4  (chunk_size)
pub const HEADER_SIZE_V1: usize = 8 + 1 + SALT_SIZE + BASE_NONCE_SIZE + 4;

/// SealVault v2 Header 固定大小
///
/// 8  (magic)
/// 1  (version)
/// 1  (algorithm)
/// 16 (salt)
/// 24 (base_nonce)
/// 4  (chunk_size)
pub const HEADER_SIZE_V2: usize = 8 + 1 + 1 + SALT_SIZE + BASE_NONCE_SIZE + 4;

/// 当前 Header 固定大小
pub const HEADER_SIZE: usize = HEADER_SIZE_V2;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub algorithm: AeadAlgorithm,
    pub salt: [u8; SALT_SIZE],
    pub base_nonce: [u8; BASE_NONCE_SIZE],
    pub chunk_size: u32,
}

impl Header {
    pub fn new(
        salt: [u8; SALT_SIZE],
        base_nonce: [u8; BASE_NONCE_SIZE],
        chunk_size: u32,
        algorithm: AeadAlgorithm,
    ) -> Self {
        Self {
            version: VERSION,
            algorithm,
            salt,
            base_nonce,
            chunk_size,
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(MAGIC)?;
        writer.write_all(&[self.version])?;

        if self.version >= VERSION_V2 {
            writer.write_all(&[self.algorithm.to_u8()])?;
        }

        writer.write_all(&self.salt)?;
        writer.write_all(&self.base_nonce)?;
        writer.write_all(&self.chunk_size.to_be_bytes())?;

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;

        if &magic != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SealVault magic",
            ));
        }

        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf)?;
        let version = version_buf[0];

        let algorithm = match version {
            VERSION_V1 => DEFAULT_AEAD_ALGORITHM,
            VERSION_V2 => {
                let mut algorithm_buf = [0u8; 1];
                reader.read_exact(&mut algorithm_buf)?;
                AeadAlgorithm::from_u8(algorithm_buf[0]).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unsupported SealVault algorithm",
                    )
                })?
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported SealVault version",
                ));
            }
        };

        let mut salt = [0u8; SALT_SIZE];
        reader.read_exact(&mut salt)?;

        let mut base_nonce = [0u8; BASE_NONCE_SIZE];
        reader.read_exact(&mut base_nonce)?;

        let mut chunk_size_buf = [0u8; 4];
        reader.read_exact(&mut chunk_size_buf)?;
        let chunk_size = u32::from_be_bytes(chunk_size_buf);

        if chunk_size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid chunk size",
            ));
        }

        Ok(Self {
            version,
            algorithm,
            salt,
            base_nonce,
            chunk_size,
        })
    }
}
