//! SealVault 解密流程实现
//!
//! 本模块负责将 .svlt 文件解密还原为原始文件。
//!
//! 解密流程（严格顺序）：
//! 1. 读取并校验 Header
//! 2. 使用 Header 中的 salt + 密码派生 AEAD key
//! 3. 初始化 StreamDecryptor
//! 4. 流式解密剩余数据
//!
//! 注意：
//! - 若 Header 或任一 chunk 校验失败，必须立即报错
//! - 本模块不负责覆盖保护或原子写入

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use crate::crypto::kdf;
use crate::format::header::Header;
use crate::format::stream::StreamDecryptor;
use argon2::password_hash::SaltString;

/// 使用密码解密文件
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
) -> std::io::Result<()> {
    // ---------- 打开输入 / 输出文件 ----------
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;

    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);

    // ---------- 读取并校验 Header ----------
    let header = Header::read(&mut reader)?;
    let salt = header.salt;

    // ---------- KDF 派生密钥 ----------
    let salt_string =
        SaltString::encode_b64(&salt)
           .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData, 
                    format!("encode salt failed: {e}"),
                )
            })?;

    let key =
        kdf::derive_key(password, &salt_string)
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
            })?;

    // ---------- Stream 解密 ----------
    let mut decryptor = StreamDecryptor::new(
        &key,
        header.base_nonce,
    );

    decryptor.decrypt(&mut reader, &mut writer)?;

    writer.flush()?;

    Ok(())
}
