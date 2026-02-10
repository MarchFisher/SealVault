//! SealVault 加密流程实现

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use argon2::password_hash::SaltString;
use rand::{RngCore, rngs::OsRng};

use crate::crypto::kdf;
use crate::format::header::{AeadAlgorithm, BASE_NONCE_SIZE, Header, SALT_SIZE};
use crate::format::stream::{DEFAULT_CHUNK_SIZE, StreamEncryptor};

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
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;

    let reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let mut base_nonce = [0u8; BASE_NONCE_SIZE];
    OsRng.fill_bytes(&mut base_nonce);

    let header = Header::new(salt, base_nonce, DEFAULT_CHUNK_SIZE as u32, algorithm);
    header.write(&mut writer)?;

    let salt_string = SaltString::encode_b64(&salt).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("encode salt failed: {e}"),
        )
    })?;

    let key = kdf::derive_key(password, &salt_string)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut encryptor =
        StreamEncryptor::new(&key, base_nonce, DEFAULT_CHUNK_SIZE, header.algorithm);
    encryptor.encrypt(reader, &mut writer)?;

    writer.flush()?;
    Ok(())
}
