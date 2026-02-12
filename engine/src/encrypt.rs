//! SealVault 加密流程实现
//!
//! 本模块负责将一个普通文件加密为 .svlt 文件。
//!
//! 加密流程（严格顺序）：
//! 1. 生成 salt 与 base_nonce
//! 2. 写入 Header
//! 3. 使用 KDF 从密码派生 AEAD key
//! 4. 使用 StreamEncryptor 对文件内容进行流式加密
//!
//! 注意：
//! - 不处理文件夹
//! - 不做 UI / 密码输入

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use argon2::password_hash::SaltString;
use rand::{RngCore, rngs::OsRng};

use crate::algorithm::AeadAlgorithm;
use crate::crypto::kdf;
use crate::format::header::{BASE_NONCE_SIZE, Header, SALT_SIZE};
use crate::format::stream::{DEFAULT_CHUNK_SIZE, StreamEncryptor};
use crate::fs::atomic::write_atomic;

#[allow(dead_code)]
/// 使用密码加密文件
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> std::io::Result<()> {
    encrypt_file_with_algorithm(
        input_path,
        output_path,
        password,
        AeadAlgorithm::XChaCha20Poly1305,
    )
}

pub fn encrypt_file_with_algorithm(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    algorithm: AeadAlgorithm,
) -> std::io::Result<()> {
    // ---------- 打开输入文件 ----------
    let input = File::open(input_path)?;

    let reader = BufReader::new(input);

    // ---------- 生成 salt ----------
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    // ---------- 生成 base nonce ----------
    let mut base_nonce = [0u8; BASE_NONCE_SIZE];
    OsRng.fill_bytes(&mut base_nonce);

    // ---------- KDF 派生密钥 ----------
    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let key = kdf::derive_key(password, &salt_string)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    // ---------- Stream 加密 ----------
    let mut encryptor = StreamEncryptor::new(&key, algorithm, base_nonce, DEFAULT_CHUNK_SIZE);

    write_atomic(output_path, |output| {
        let mut writer = BufWriter::new(output);

        // ---------- 写入 Header ----------
        let header = Header::new(algorithm, salt, base_nonce, DEFAULT_CHUNK_SIZE as u32);
        header.write(&mut writer)?;

        encryptor.encrypt(reader, &mut writer)?;

        // 确保所有数据落盘
        writer.flush()?;
        Ok(())
    })?;

    Ok(())
}
