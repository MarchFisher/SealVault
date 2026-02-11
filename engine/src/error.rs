use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealVaultError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("invalid password or not a SealVault file")]
    _InvalidPasswordOrFile,

    #[error("unsupported SealVault version")]
    _UnsupportedVersion,

    #[error("corrupted data")]
    _CorruptedData,

    #[error("output already exists")]
    _AlreadyExists,

    #[error("internal error")]
    Internal,
}
