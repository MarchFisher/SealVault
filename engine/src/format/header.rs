//! SealVault v1 Header 实现
//!
//! 本模块定义并实现 SealVault v1 文件格式中的 Header 部分。
//!
//! Header 的职责：
//! - 标识文件类型（magic）
//! - 指明版本号
//! - 指明 AEAD 算法
//! - 提供密钥派生所需的 salt
//! - 提供 Stream 所需的 base_nonce
//! - 指明 stream 的 chunk_size
//!
//! Header 是整个 .svlt 文件的“格式锚点”：
//! - 解密前必须完整读取并校验 Header
//! - Header 一旦解析失败，必须拒绝继续处理
//!
//! SealVault v1 Header 为固定结构，后续版本只能：
//! - bump version
//! - 或在 Header 后追加扩展区

use std::io::{Read, Write};

use crate::algorithm::AeadAlgorithm;

/// SealVault 文件魔数（ASCII）
///
/// 用于快速判断文件类型，避免误读。
pub const MAGIC: &[u8; 8] = b"SVLTv1\0\0";

/// 当前支持的版本号
pub const VERSION: u8 = 1;

/// KDF 使用的 salt 长度（字节）
pub const SALT_SIZE: usize = 16;

/// XChaCha20-Poly1305 base nonce 长度（字节）
/// AES-256-GCM 实际使用前 12 字节
pub const BASE_NONCE_SIZE: usize = 24;

/// SealVault v1 Header 固定大小
///
/// 8  (magic)
/// 1  (version)
/// 1  (algorithm)
/// 16 (salt)
/// 24 (base_nonce)
/// 4  (chunk_size)
pub const HEADER_SIZE: usize = 8 + 1 + 1 + SALT_SIZE + BASE_NONCE_SIZE + 4;

/// SealVault v1 Header 结构
///
/// 该结构仅表示 Header 的“语义内容”，
/// 具体的字节序列化由 read / write 方法负责。
#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub algorithm: AeadAlgorithm,
    pub salt: [u8; SALT_SIZE],
    pub base_nonce: [u8; BASE_NONCE_SIZE],
    pub chunk_size: u32,
}

impl Header {
    /// 创建新的 v1 Header
    ///
    /// 该函数通常在加密时调用。
    pub fn new(
        algorithm: AeadAlgorithm,
        salt: [u8; SALT_SIZE],
        base_nonce: [u8; BASE_NONCE_SIZE],
        chunk_size: u32,
    ) -> Self {
        Self {
            version: VERSION,
            algorithm,
            salt,
            base_nonce,
            chunk_size,
        }
    }

    /// 将 Header 写入输出流
    ///
    /// 写入顺序和字节布局必须严格遵循 v1 规范。
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        // magic
        writer.write_all(MAGIC)?;

        // version
        writer.write_all(&[self.version])?;

        // algorithm
        writer.write_all(&[self.algorithm.to_u8()])?;

        // salt
        writer.write_all(&self.salt)?;

        // base nonce
        writer.write_all(&self.base_nonce)?;

        // chunk size（大端）
        writer.write_all(&self.chunk_size.to_be_bytes())?;

        Ok(())
    }

    /// 从输入流读取并解析 Header
    ///
    /// 该函数通常在解密时调用。
    /// 若 Header 不合法，必须返回错误。
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
            VERSION => {
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
