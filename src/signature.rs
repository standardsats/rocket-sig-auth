use rocket::{
    data::{Limits, Outcome},
    http::Status,
    serde::Deserialize,
};
use rocket_okapi::{
    gen::OpenApiGenerator,
    okapi::{
        openapi3::{MediaType, RequestBody},
        Map,
    },
    request::OpenApiFromData,
    JsonSchema,
};
use std::{io, marker::PhantomData, str::FromStr};

use crate::{
    error::Error,
    types::{PermissionCheck, PublicKey, PublicKeyAuth},
    HasPublicKeyAuth,
};
use rocket::data::FromData;
use secp256k1::{hashes::sha256, Message, Secp256k1};

#[rocket::async_trait]
impl<
        'a,
        const PERM: u8,
        Perm: TryFrom<u8>,
        AuthInfo,
        PermProvider: HasPublicKeyAuth<Perm, AuthInfo> + Send + Sync + 'static,
        T: for<'de> Deserialize<'de>,
    > FromData<'a> for PublicKeyAuth<Perm, AuthInfo, PermProvider, PERM, T>
{
    type Error = crate::error::Error;

    async fn from_data(req: &'a rocket::Request<'_>, data: rocket::Data<'a>) -> Outcome<'a, Self> {
        let pp = req.rocket().state::<PermProvider>();
        if pp.is_none() {
            return Outcome::Failure((Status::Unauthorized, Error::NoProvider));
        };
        let pp = pp.unwrap();

        let sig = req.headers().get_one("X-Signature");
        if sig.is_none() {
            return Outcome::Failure((Status::Unauthorized, Error::MissingXSig));
        };
        let sig = sig.unwrap();

        let nonce = req.headers().get_one("X-Nonce");
        if nonce.is_none() {
            return Outcome::Failure((Status::Unauthorized, Error::MissingXNonce));
        };
        let nonce = nonce.unwrap();

        let timeout = pp.get_nonce_timeout().await;

        if let Ok(nonce) = nonce.parse::<i64>() {
            let now = chrono::Utc::now().naive_utc().timestamp();
            if now.abs_diff(nonce) > timeout {
                return Outcome::Failure((Status::Unauthorized, Error::NonceTooOld));
            }
        } else {
            return Outcome::Failure((Status::Unauthorized, Error::NonceDecodeError));
        };

        let public_key = req.headers().get_one("X-Public-Key");
        if public_key.is_none() {
            return Outcome::Failure((Status::Unauthorized, Error::MissingXPubKey));
        };
        let public_key = public_key.unwrap();

        let uri = req.uri();
        let domain = pp.get_domain().await;

        let mut data_bytes: Vec<u8> = vec![];
        let limit = req.limits().get("json").unwrap_or(Limits::JSON);

        match data.open(limit).stream_to(&mut data_bytes).await {
            Ok(s) if !s.complete => {
                let err = Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "data limit exceeded",
                ));
                return Outcome::Failure((Status::BadRequest, err));
            }
            Err(e) => return Outcome::Failure((Status::BadRequest, Error::Io(e))),
            _ => {}
        };

        if let Err(e) = check_signature(
            &data_bytes,
            sig,
            public_key,
            &domain,
            &uri.to_string(),
            nonce,
        ) {
            return Outcome::Failure((Status::Unauthorized, e));
        };

        // Here we assume signature check is ok
        match pp
            .check_permission(PublicKey(public_key.to_string()), PERM)
            .await
        {
            PermissionCheck::Success(auth) => {
                // We have to put the bytes in the requests local cahe so they outlive the guard
                let bytes = rocket::request::local_cache!(req, data_bytes);
                match serde_json::from_slice(bytes) {
                    Ok(data) => Outcome::Success(PublicKeyAuth {
                        auth,
                        data,
                        phantom_perm: PhantomData,
                        phantom_provider: PhantomData,
                    }),
                    Err(e) => Outcome::Failure((Status::BadRequest, Error::Parse(e))),
                }
            }
            PermissionCheck::Error(e) => {
                Outcome::Failure((Status::InternalServerError, Error::PermissionCheckError(e)))
            }
            PermissionCheck::Unauthorized => {
                Outcome::Failure((Status::Unauthorized, Error::Unauthorized))
            }
            PermissionCheck::PermissionDenied => {
                Outcome::Failure((Status::Forbidden, Error::Forbidden))
            }
        }
    }
}

impl<
        'a,
        const PERM: u8,
        Perm: TryFrom<u8>,
        AuthInfo,
        PermProvider: HasPublicKeyAuth<Perm, AuthInfo> + Send + Sync + 'static,
        T: for<'de> Deserialize<'de> + JsonSchema,
    > OpenApiFromData<'a> for PublicKeyAuth<Perm, AuthInfo, PermProvider, PERM, T>
{
    fn request_body(
        gen: &mut OpenApiGenerator,
    ) -> rocket_okapi::Result<rocket_okapi::okapi::openapi3::RequestBody> {
        let schema = gen.json_schema::<T>();
        Ok(RequestBody {
            content: {
                let mut map = Map::new();
                map.insert(
                    "application/json".to_owned(),
                    MediaType {
                        schema: Some(schema),
                        ..Default::default()
                    },
                );
                map
            },
            required: true,
            ..Default::default()
        })
    }
}

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
