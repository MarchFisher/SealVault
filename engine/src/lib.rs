mod decrypt;
mod encrypt;
mod folder;

pub mod algorithm;
pub mod crypto;
pub mod error;
pub mod format;
pub mod fs;

pub use algorithm::AeadAlgorithm;
pub use error::SealVaultError;

use std::path::Path;

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

pub fn encrypt_folder(
    input: &Path,
    output: &Path,
    password: &str,
    algorithm: AeadAlgorithm,
) -> std::io::Result<()> {
    folder::encrypt_folder(input, output, password, algorithm)
}

pub fn decrypt_folder(
    input: &Path,
    output: &Path,
    password: &str,
    algorithm: AeadAlgorithm,
) -> std::io::Result<()> {
    folder::decrypt_folder(input, output, password, algorithm)
}
