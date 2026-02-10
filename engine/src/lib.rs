mod decrypt;
mod encrypt;

pub mod crypto;
pub mod error;
pub mod format;
pub mod fs;

pub use error::SealVaultError;
use std::path::Path;

pub use format::header::AeadAlgorithm;

pub fn encrypt(input: &Path, output: &Path, password: &str) -> std::io::Result<()> {
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

pub fn decrypt(input: &Path, output: &Path, password: &str) -> std::io::Result<()> {
    decrypt::decrypt_file(input, output, password)
}
