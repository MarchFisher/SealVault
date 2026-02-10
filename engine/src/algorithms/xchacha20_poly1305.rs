//! SealVault XChaCha20-Poly1305 加解密算法

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

pub const NONCE_SIZE: usize = 24;

pub fn encrypt_chunk(
    key: &[u8; 32],
    base_nonce: &[u8; 24],
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = derive_nonce(base_nonce, chunk_index);

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

pub fn decrypt_chunk(
    key: &[u8; 32],
    base_nonce: &[u8; 24],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = derive_nonce(base_nonce, chunk_index);

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

fn derive_nonce(base: &[u8; NONCE_SIZE], index: u64) -> XNonce {
    let mut nonce = *base;
    let idx_bytes = index.to_be_bytes();

    for i in 0..8 {
        nonce[16 + i] ^= idx_bytes[i];
    }

    *XNonce::from_slice(&nonce)
}
