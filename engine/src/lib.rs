mod encrypt;
mod decrypt;

pub mod algorithm;
pub mod crypto;
pub mod format;
pub mod fs;
pub mod error;

pub use error::SealVaultError;
pub use algorithm::AeadAlgorithm;

use std::path::Path;

pub fn encrypt(
    input: &Path,
    output: &Path,
    password: &str,
) -> std::io::Result<()> {
    encrypt::encrypt_file(input, output, password)
}

pub fn encrypt_with_algorithm(
    input: &Path,
    output: &Path,
    password: &str,
    algorithm: AeadAlgorithm,
) -> std::io::Result<()> {
    encrypt::encrypt_file_with_algorithm(input, output, password, algorithm)
}

pub fn decrypt(
    input: &Path,
    output: &Path,
    password: &str,
) -> std::io::Result<()> {
    decrypt::decrypt_file(input, output, password)
}
