//! SealVault AEAD 加解密模块
//!
//! 本模块基于 AES-256-GCM 实现 AEAD（Authenticated Encryption
//! with Associated Data）。
//!
//! 功能说明：
//! - 提供“加密 + 完整性校验”一体化能力
//! - 解密失败即表示：密码错误 或 数据被篡改
//! - 使用随机 nonce，严禁复用
//!
//! 安全约束：
//! - 每次加密必须使用全新的 nonce
//! - 不允许在未校验通过的情况下输出任何明文

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use crate::error::SealVaultError;

/// AES-GCM 使用的 nonce 长度（96 bit，标准推荐值）
pub const NONCE_LEN: usize = 12;

/// 加密结果结构
///
/// nonce 需要与密文一同保存，用于解密
pub struct EncryptedData {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// 使用 AES-256-GCM 加密数据
///
/// #### 参数
/// - `key_bytes`：32 字节对称密钥（来自 KDF）
/// - `plaintext`：待加密的数据
///
/// #### 返回
/// - EncryptedData（包含 nonce 和密文）
///
/// #### 安全说明
/// - 每次调用都会生成全新的随机 nonce
/// - nonce 复用会严重破坏 AES-GCM 安全性
pub fn encrypt(
    key_bytes: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedData, SealVaultError> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // 生成随机 nonce（96 bit）
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SealVaultError::Internal)?;

    Ok(EncryptedData {
        nonce: nonce.into(),
        ciphertext,
    })
}

/// 使用 AES-256-GCM 解密数据
///
/// # 参数
/// - `key_bytes`：32 字节对称密钥（来自 KDF）
/// - `nonce`：加密时使用的 nonce
/// - `ciphertext`：密文数据
///
/// # 返回
/// - 解密后的明文
///
/// # 错误
/// - 若密码错误或数据被篡改，返回 InvalidPasswordOrFile
///
/// # 安全保证
/// - 在认证未通过前，不会泄露任何明文数据
pub fn decrypt(
    key_bytes: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SealVaultError> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SealVaultError::InvalidPasswordOrFile)
}
