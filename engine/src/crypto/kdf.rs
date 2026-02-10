//! SealVault 密钥派生函数（KDF）模块
//!
//! 本模块负责将用户输入的密码，通过 Argon2id 算法
//! 派生为高强度的对称加密密钥，用于后续 AES-256-GCM 加解密。
//!
//! 设计目标：
//! - 抵抗暴力破解、GPU / ASIC 攻击
//! - 每个加密文件使用独立的随机 salt
//! - 敏感密钥材料在离开作用域后自动清零
//! - 参数可在未来通过版本号升级而不破坏兼容性
//!
//! 输出：
//! - 32 字节密钥（适用于 XChaCha20-Poly1305 / AES-256-GCM）

use argon2::{ password_hash::SaltString, Algorithm, Argon2, Params, Version };
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::SealVaultError;

/// 派生密钥长度（256-bit）
pub const KEY_LEN: usize = 32;

/// Argon2 参数配置（SealVault v1）
///
/// 该参数组合在安全性与性能之间取得平衡，
/// 后续如需调整，应通过文件格式版本号控制。
fn argon2_params() -> Params {
    Params::new(
        64 * 1024, // 内存成本：64 MB
        3,         // 时间成本：迭代次数
        1,         // 并行度
        Some(KEY_LEN as usize),
    )
    .expect("Argon2 参数配置错误")
}

/// 生成用于 KDF 的随机 salt
///
/// 每个 .svlt 文件都必须使用独立的 salt，
/// 严禁复用。
pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

/// 根据密码和 salt 派生对称加密密钥
///
/// #### 参数
/// - `password`：用户输入的密码（UTF-8）
/// - `salt`：该文件对应的随机 salt
///
/// #### 返回
/// - 32 字节派生密钥（自动 zeroize）
///
/// #### 错误
/// - 发生不可预期错误时返回 SealVaultError::Internal
pub fn derive_key(
    password: &str,
    salt: &SaltString,
) -> Result<Zeroizing<[u8; KEY_LEN]>, SealVaultError> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_params(),
    );

    // 使用 Zeroizing 包装，确保密钥在作用域结束后被清零
    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    argon2
        .hash_password_into(
            password.as_bytes(), 
            salt.as_str().as_bytes(), 
            &mut key[..]
        )
        .map_err(|_| SealVaultError::Internal)?;

    Ok(key)
}
