use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealVaultError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("invalid password or not a SealVault file")]
    InvalidPasswordOrFile,

    #[error("unsupported SealVault version")]
    UnsupportedVersion,

    #[error("corrupted data")]
    CorruptedData,

    #[error("output already exists")]
    AlreadyExists,

    #[error("internal error")]
    Internal,
}
