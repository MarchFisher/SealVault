//! SealVault 解密流程实现

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use argon2::password_hash::SaltString;

use crate::crypto::kdf;
use crate::format::header::Header;
use crate::format::stream::StreamDecryptor;

pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> std::io::Result<()> {
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;

    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);

    let header = Header::read(&mut reader)?;
    let salt = header.salt;

    let salt_string = SaltString::encode_b64(&salt).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("encode salt failed: {e}"),
        )
    })?;

    let key = kdf::derive_key(password, &salt_string)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut decryptor = StreamDecryptor::new(&key, header.base_nonce, header.algorithm);
    decryptor.decrypt(&mut reader, &mut writer)?;

    writer.flush()?;
    Ok(())
}
