mod encrypt;
mod decrypt;

pub mod crypto;
pub mod format;
pub mod fs;
pub mod error;

pub use error::SealVaultError;

use std::path::Path;

pub fn encrypt(
    input: &Path,
    output: &Path,
    password: &str,
) -> std::io::Result<()> {
    encrypt::encrypt_file(input, output, password)
}

pub fn decrypt(
    input: &Path,
    output: &Path,
    password: &str,
) -> std::io::Result<()> {
    decrypt::decrypt_file(input, output, password)
}
