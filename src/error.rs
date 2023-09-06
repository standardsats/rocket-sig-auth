use std::{fmt::Debug, io};

use thiserror::Error;

#[derive(Error)]
pub enum Error {
    #[error("Failed to decode hex public key: {0}")]
    KeyDecode(secp256k1::Error),
    #[error("Failed to decode DER signature: {0}")]
    SignatureDecode(secp256k1::Error),
    #[error("Signature check failed: {0}")]
    SignatureVerify(secp256k1::Error),
    #[error("Missing authorization header")]
    MissingAuthHeader,
    #[error("Permission check: {0}")]
    PermissionCheckError(String),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Forbidden. Requester lacks permission")]
    Forbidden,
    #[error("Missing X-Signature header")]
    MissingXSig,
    #[error("Missing X-Public-Key header")]
    MissingXPubKey,
    #[error("Missing X-Nonce header")]
    MissingXNonce,
    #[error("Failed to decode nonce. Expected a UNIX timestamp as i64")]
    NonceDecodeError,
    #[error("Nonce is too old. Repeat the request with a fresh nonce")]
    NonceTooOld,
    #[error("{0}")]
    Io(io::Error),
    #[error("{0}")]
    Parse(serde_json::error::Error),
    #[error("Failed to get the provider")]
    NoProvider,
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
