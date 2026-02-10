//! SealVault Stream 实现
//!
//! 支持 XChaCha20-Poly1305 与 AES-256-GCM 两种 AEAD 算法。

use std::io::{Read, Write};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::format::header::{AeadAlgorithm, BASE_NONCE_SIZE};

const TAG_SIZE: usize = 16;
const LEN_SIZE: usize = 4;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

pub struct StreamEncryptor {
    cipher: CipherImpl,
    base_nonce: [u8; BASE_NONCE_SIZE],
    chunk_index: u64,
    chunk_size: usize,
}

pub struct StreamDecryptor {
    cipher: CipherImpl,
    base_nonce: [u8; BASE_NONCE_SIZE],
    chunk_index: u64,
}

enum CipherImpl {
    XChaCha20Poly1305(XChaCha20Poly1305),
    Aes256Gcm(Aes256Gcm),
}

impl CipherImpl {
    fn new(algorithm: AeadAlgorithm, key: &[u8; 32]) -> Self {
        match algorithm {
            AeadAlgorithm::XChaCha20Poly1305 => {
                Self::XChaCha20Poly1305(XChaCha20Poly1305::new(Key::from_slice(key)))
            }
            AeadAlgorithm::Aes256Gcm => {
                Self::Aes256Gcm(Aes256Gcm::new_from_slice(key).expect("invalid AES key length"))
            }
        }
    }

    fn encrypt(
        &self,
        base_nonce: &[u8; BASE_NONCE_SIZE],
        chunk_index: u64,
        plaintext: &[u8],
        aad: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        match self {
            CipherImpl::XChaCha20Poly1305(cipher) => {
                let nonce = derive_nonce_xchacha(base_nonce, chunk_index);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| std::io::Error::other("AEAD encrypt failed"))
            }
            CipherImpl::Aes256Gcm(cipher) => {
                let nonce_bytes = derive_nonce_aes(base_nonce, chunk_index);
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| std::io::Error::other("AEAD encrypt failed"))
            }
        }
    }

    fn decrypt(
        &self,
        base_nonce: &[u8; BASE_NONCE_SIZE],
        chunk_index: u64,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        match self {
            CipherImpl::XChaCha20Poly1305(cipher) => {
                let nonce = derive_nonce_xchacha(base_nonce, chunk_index);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "AEAD authentication failed",
                        )
                    })
            }
            CipherImpl::Aes256Gcm(cipher) => {
                let nonce_bytes = derive_nonce_aes(base_nonce, chunk_index);
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "AEAD authentication failed",
                        )
                    })
            }
        }
    }
}

impl StreamEncryptor {
    pub fn new(
        key: &[u8; 32],
        base_nonce: [u8; BASE_NONCE_SIZE],
        chunk_size: usize,
        algorithm: AeadAlgorithm,
    ) -> Self {
        Self {
            cipher: CipherImpl::new(algorithm, key),
            base_nonce,
            chunk_index: 0,
            chunk_size,
        }
    }

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
            let aad = self.chunk_index.to_be_bytes();

            let ciphertext =
                self.cipher
                    .encrypt(&self.base_nonce, self.chunk_index, plaintext, &aad)?;

            let cipher_len = ciphertext.len() - TAG_SIZE;
            let (cipher_body, tag) = ciphertext.split_at(cipher_len);

            writer.write_all(&(cipher_body.len() as u32).to_be_bytes())?;
            writer.write_all(cipher_body)?;
            writer.write_all(tag)?;

            self.chunk_index += 1;
        }

        Ok(())
    }
}

impl StreamDecryptor {
    pub fn new(
        key: &[u8; 32],
        base_nonce: [u8; BASE_NONCE_SIZE],
        algorithm: AeadAlgorithm,
    ) -> Self {
        Self {
            cipher: CipherImpl::new(algorithm, key),
            base_nonce,
            chunk_index: 0,
        }
    }

    pub fn decrypt<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        loop {
            let mut len_buf = [0u8; LEN_SIZE];

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
            let plaintext =
                self.cipher
                    .decrypt(&self.base_nonce, self.chunk_index, &cipher_body, &aad)?;

            writer.write_all(&plaintext)?;
            self.chunk_index += 1;
        }

        Ok(())
    }
}

fn derive_nonce_xchacha(base: &[u8; BASE_NONCE_SIZE], index: u64) -> XNonce {
    let mut nonce = *base;
    let idx_bytes = index.to_be_bytes();

    for i in 0..8 {
        nonce[16 + i] ^= idx_bytes[i];
    }

    XNonce::from_slice(&nonce).clone()
}

fn derive_nonce_aes(base: &[u8; BASE_NONCE_SIZE], index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&base[..12]);

    let idx_bytes = index.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= idx_bytes[i];
    }

    nonce
}
