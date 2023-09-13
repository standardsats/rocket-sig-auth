use std::str::FromStr;

use secp256k1::{hashes::sha256, Message, Secp256k1};

use crate::error::Error;

pub mod bytes;
pub mod json;

/// Check that signature of data and user pubkey is valid and return `Ok(())` in that case.
pub fn check_signature(
    data: &[u8],
    sig: &str,
    key: &str,
    domain: &str,
    uri: &str,
    nonce: &str,
) -> Result<(), Error> {
    let prefix = [domain, uri, nonce].concat();
    let prefix = prefix.as_bytes();
    let message_bytes = [prefix, data].concat();
    let message = Message::from_hashed_data::<sha256::Hash>(&message_bytes);
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_str(key).map_err(Error::KeyDecode)?;
    let signature = secp256k1::ecdsa::Signature::from_str(sig).map_err(Error::SignatureDecode)?;
    secp.verify_ecdsa(&message, &signature, &public_key)
        .map_err(Error::SignatureVerify)?;
    Ok(())
}
