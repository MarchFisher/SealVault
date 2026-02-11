//! SealVault AES-256-GCM 加解密算法

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};

pub const NONCE_SIZE: usize = 12;

pub fn encrypt_chunk(
    key: &[u8; 32],
    base_nonce: &[u8; 24],
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid key length"))?;
    let nonce_bytes = derive_nonce(base_nonce, chunk_index);
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

pub fn decrypt_chunk(
    key: &[u8; 32],
    base_nonce: &[u8; 24],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid key length"))?;
    let nonce_bytes = derive_nonce(base_nonce, chunk_index);
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

fn derive_nonce(base: &[u8; 24], index: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&base[..NONCE_SIZE]);

    let idx_bytes = index.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= idx_bytes[i];
    }

    nonce
}
