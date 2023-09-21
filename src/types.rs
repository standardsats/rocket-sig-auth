use std::{fmt::Display, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::{HasCombinedAuth, HasPublicKeyAuth, HasTokenAuth};

/// Api token wrapper
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Token(pub String);

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Public key wrapper
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicKey(pub String);

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Result of a permission check. Auth info is passed to the handler
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionCheck<AuthInfo> {
    // Permission granted
    Success(AuthInfo),
    // Token or public key not found
    Unauthorized,
    // Token or public key is found, but lacks permission
    PermissionDenied,
    // Some error happend. String for ease of implementation
    Error(String),
}

/// Type implementing rocket request guard for token authorization scheme
/// Passes auth info to handler
/// Phantoms are required to keep the compiler happy
pub struct TokenAuth<Perm, AuthInfo, Provider, const PERM: u8>
where
    Perm: TryFrom<u8>,
    Provider: HasTokenAuth<Perm, AuthInfo>,
{
    pub auth: AuthInfo,
    pub phantom_perm: PhantomData<Perm>,
    pub phantom_provider: PhantomData<Provider>,
}

/// Type implementing rocket request guard for public key authorization scheme
/// Passes auth info and data to handler
/// Phantoms are required to keep the compiler happy
pub struct PublicKeyAuth<Perm, AuthInfo, Provider, const PERM: u8, T>
where
    Perm: TryFrom<u8>,
    Provider: HasPublicKeyAuth<Perm, AuthInfo>,
    T: for<'de> Deserialize<'de>,
{
    pub auth: AuthInfo,
    pub data: T,
    pub phantom_perm: PhantomData<Perm>,
    pub phantom_provider: PhantomData<Provider>,
}

/// Type implementing rocket request guard for combined authorization scheme
/// Passes auth info and data to handler
/// Phantoms are required to keep the compiler happy
pub struct CombinedAuth<Perm, AuthInfo, Provider, const PERM: u8, T>
where
    Perm: TryFrom<u8>,
    Provider: HasCombinedAuth<Perm, AuthInfo>,
    T: for<'de> Deserialize<'de>,
{
    pub auth: AuthInfo,
    pub data: T,
    pub phantom0: PhantomData<Perm>,
    pub phantom1: PhantomData<Provider>,
}

/// Type implementing rocket request guard for public key authorization scheme
/// Passes auth info and data to handler
/// Phantoms are required to keep the compiler happy
pub struct PublicKeyBytesAuth<Perm, AuthInfo, Provider, const PERM: u8>
where
    Perm: TryFrom<u8>,
    Provider: HasPublicKeyAuth<Perm, AuthInfo>,
{
    pub auth: AuthInfo,
    pub data: Vec<u8>,
    pub phantom_perm: PhantomData<Perm>,
    pub phantom_provider: PhantomData<Provider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthSchemaTag {
    SigJson,
    SigBytes,
    ApiToken,
    Combined,
}
