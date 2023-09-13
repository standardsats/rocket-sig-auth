use async_trait::async_trait;
use types::{PermissionCheck, PublicKey, Token};

pub mod combined;
pub mod error;
pub mod signature;
pub mod token;
pub mod types;

/// Token authorization scheme
/// Permission has to be convertible to and from u8
/// Provides implementation for RequestGuad
/// which checks bearer auth header
#[async_trait]
pub trait HasTokenAuth<Perm, AuthInfo>
where
    // Not actually used, but kept as a reminder
    Perm: TryFrom<u8>,
{
    /// Check token's permission to access handler
    /// u8 -> Perm is handled inside the implementation
    async fn check_permission(&self, token: Token, perm: u8) -> PermissionCheck<AuthInfo>;
}

/// Secp256k1 public key signature authorization
/// Requires headers:
/// X-Signature: der-encoded secp256k1 signature of concatenation of
/// domain + uri (w/o parameters) + data bytes
/// X-Public-Key: hex-encoded bytes of secp256k1 public key
/// X-Nonce: UTC timestamp in seconds as String
#[async_trait]
pub trait HasPublicKeyAuth<Perm, AuthInfo>
where
    Perm: TryFrom<u8>,
{
    /// Check public key's permission to access handler
    async fn check_permission(&self, public_key: PublicKey, perm: u8) -> PermissionCheck<AuthInfo>;

    /// Get domain prefix used by both the server and the client. Must be the same
    /// Uri is extracted from the request
    async fn get_domain(&self) -> String;

    /// Get nonce timeout in seconds
    /// If current timestamp and nonce timestamp differ for more than the timeout, access is forbidden
    async fn get_nonce_timeout(&self) -> u64;
}

/// Combined authorization scheme
/// Firstly check bearer auth header. If present, use the token authorization
/// If not -- fallback to public key authorization scheme
#[async_trait]
pub trait HasCombinedAuth<Perm, AuthInfo>
where
    Perm: TryFrom<u8>,
{
    /// Check token's permission to access handler
    /// u8 -> Perm is handled inside the implementation
    async fn check_permission_by_token(&self, token: Token, perm: u8) -> PermissionCheck<AuthInfo>;

    /// Check public key's permission to access handler
    async fn check_permission_by_public_key(
        &self,
        public_key: PublicKey,
        perm: u8,
    ) -> PermissionCheck<AuthInfo>;

    /// Get domain prefix used by both the server and the client. Must be the same for both
    /// Uri is extracted from the request
    async fn get_domain(&self) -> String;

    /// Get nonce timeout in seconds
    /// If current timestamp and nonce timestamp differ for more than the timeout, access is forbidden
    async fn get_nonce_timeout(&self) -> u64;
}

// Default implementation of CombinedAuth in case the provider has both Token and Public key implemented
#[async_trait]
impl<
        Perm: TryFrom<u8>,
        AuthInfo,
        T: HasTokenAuth<Perm, AuthInfo> + HasPublicKeyAuth<Perm, AuthInfo> + Sync,
    > HasCombinedAuth<Perm, AuthInfo> for T
{
    async fn check_permission_by_token(&self, token: Token, perm: u8) -> PermissionCheck<AuthInfo> {
        <T as HasTokenAuth<Perm, AuthInfo>>::check_permission(self, token, perm).await
    }

    async fn check_permission_by_public_key(
        &self,
        public_key: PublicKey,
        perm: u8,
    ) -> PermissionCheck<AuthInfo> {
        <T as HasPublicKeyAuth<Perm, AuthInfo>>::check_permission(self, public_key, perm).await
    }

    async fn get_domain(&self) -> String {
        <T as HasPublicKeyAuth<Perm, AuthInfo>>::get_domain(self).await
    }

    async fn get_nonce_timeout(&self) -> u64 {
        <T as HasPublicKeyAuth<Perm, AuthInfo>>::get_nonce_timeout(self).await
    }
}
