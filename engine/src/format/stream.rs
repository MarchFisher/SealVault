//! SealVault v1 Stream 实现
//!
//! 本模块负责 SealVault v1 中“数据流（Stream）”部分的加密与解密。
//!
//! 职责范围：
//! - 将任意大小的输入数据按固定大小分割为多个 chunk
//! - 对每个 chunk 使用 XChaCha20-Poly1305 进行独立加密与认证
//! - 按 v1 Stream 格式将加密结果顺序写入输出流
//! - 在解密时严格校验每个 chunk 的完整性与顺序
//!
//! 设计前提与约束：
//! - 仅支持单文件流式处理（不涉及文件夹、元数据）
//! - Header 已负责提供：AEAD key、base_nonce、chunk_size
//! - 每个 chunk 使用唯一 nonce，并绑定 chunk_index 作为 AAD
//! - 本模块不负责原子写入、路径处理、错误恢复策略

use std::io::{Read, Write};

use crate::algorithm::{AeadAlgorithm, aes_256_gcm, xchacha20_poly1305};
use crate::format::header::BASE_NONCE_SIZE;

// AEAD 认证标签长度，固定为 16 字节
const TAG_SIZE: usize = 16;

// 每个 chunk 前的长度字段大小（u32，大端）
const LEN_SIZE: usize = 4;

// 推荐的默认明文 chunk 大小：64 KiB
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// 流式加密器
///
/// 负责将明文数据流按 chunk 加密并写入输出流。
pub struct StreamEncryptor {
    key: [u8; 32],
    algorithm: AeadAlgorithm,
    base_nonce: [u8; BASE_NONCE_SIZE],
    chunk_index: u64,
    chunk_size: usize,
}

impl StreamEncryptor {
    /// 创建新的 StreamEncryptor
    ///
    /// - key: 32 字节 AEAD 密钥（来自 KDF）
    /// - base_nonce: Header 中生成并保存的 base nonce
    /// - chunk_size: 每个明文 chunk 的大小
    pub fn new(
        key: &[u8; 32],
        algorithm: AeadAlgorithm,
        base_nonce: [u8; BASE_NONCE_SIZE],
        chunk_size: usize,
    ) -> Self {
        Self {
            key: *key,
            algorithm,
            base_nonce,
            chunk_index: 0,
            chunk_size,
        }
    }

    /// 从 reader 读取明文数据，加密后写入 writer
    pub fn encrypt<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let read_len = reader.read(&mut buffer)?;
            if read_len == 0 {
                break;
            }

            let plaintext = &buffer[..read_len];

            // 使用 chunk_index 作为 AAD，防止块重排
            let aad = self.chunk_index.to_be_bytes();

            let ciphertext = match self.algorithm {
                AeadAlgorithm::XChaCha20Poly1305 => xchacha20_poly1305::encrypt_chunk(
                    &self.key,
                    &self.base_nonce,
                    self.chunk_index,
                    plaintext,
                    &aad,
                )?,
                AeadAlgorithm::Aes256Gcm => aes_256_gcm::encrypt_chunk(
                    &self.key,
                    &self.base_nonce,
                    self.chunk_index,
                    plaintext,
                    &aad,
                )?,
            };

            // ciphertext = [cipher_body | tag]
            let cipher_len = ciphertext.len() - TAG_SIZE;
            let (cipher_body, tag) = ciphertext.split_at(cipher_len);

            // 写入 chunk 长度（仅包含 cipher_body）
            writer.write_all(&(cipher_body.len() as u32).to_be_bytes())?;
            writer.write_all(cipher_body)?;
            writer.write_all(tag)?;

            self.chunk_index += 1;
        }

        Ok(())
    }
}

/// 流式解密器
///
/// 负责从加密 stream 中读取数据并还原明文。
pub struct StreamDecryptor {
    key: [u8; 32],
    algorithm: AeadAlgorithm,
    base_nonce: [u8; BASE_NONCE_SIZE],
    chunk_index: u64,
}

impl StreamDecryptor {
    /// 创建新的 StreamDecryptor
    pub fn new(
        key: &[u8; 32], 
        algorithm: AeadAlgorithm,
        base_nonce: [u8; BASE_NONCE_SIZE]
    ) -> Self {
        Self {
            key: *key,
            algorithm,
            base_nonce,
            chunk_index: 0,
        }
    }

    /// 从 reader 读取加密数据流，解密后写入 writer
    pub fn decrypt<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        loop {
            let mut len_buf = [0u8; LEN_SIZE];

            // 读取 chunk 长度；若在边界处 EOF，视为正常结束
            if let Err(e) = reader.read_exact(&mut len_buf) {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(e);
            }

            let cipher_len = u32::from_be_bytes(len_buf) as usize;
            if cipher_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid chunk length",
                ));
            }

            let mut cipher_body = vec![0u8; cipher_len];
            let mut tag = vec![0u8; TAG_SIZE];

            reader.read_exact(&mut cipher_body)?;
            reader.read_exact(&mut tag)?;

            cipher_body.extend_from_slice(&tag);

            let aad = self.chunk_index.to_be_bytes();

            let plaintext = match self.algorithm {
                AeadAlgorithm::XChaCha20Poly1305 => xchacha20_poly1305::decrypt_chunk(
                    &self.key,
                    &self.base_nonce,
                    self.chunk_index,
                    &cipher_body,
                    &aad,
                )?,
                AeadAlgorithm::Aes256Gcm => aes_256_gcm::decrypt_chunk(
                    &self.key,
                    &self.base_nonce,
                    self.chunk_index,
                    &cipher_body,
                    &aad,
                )?,
            };

            writer.write_all(&plaintext)?;
            self.chunk_index += 1;
        }

        Ok(())
    }
}
