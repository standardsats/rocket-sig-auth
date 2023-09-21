use rocket::{
    data::{ByteUnit, Outcome},
    http::Status,
};
use rocket_okapi::{
    gen::OpenApiGenerator,
    okapi::{
        openapi3::{MediaType, RequestBody},
        Map,
    },
    request::OpenApiFromData,
};
use std::{io, marker::PhantomData};

use crate::{
    error::Error,
    types::{AuthSchemaTag, PermissionCheck, PublicKey, PublicKeyBytesAuth},
    HasPublicKeyAuth,
};
use rocket::data::FromData;

use super::check_signature;

#[rocket::async_trait]
impl<
        'a,
        const PERM: u8,
        Perm: TryFrom<u8>,
        AuthInfo,
        PermProvider: HasPublicKeyAuth<Perm, AuthInfo> + Send + Sync + 'static,
    > FromData<'a> for PublicKeyBytesAuth<Perm, AuthInfo, PermProvider, PERM>
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

        let timeout = pp.get_nonce_timeout(AuthSchemaTag::SigBytes).await;

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

        match data
            .open(ByteUnit::Megabyte(50))
            .stream_to(&mut data_bytes)
            .await
        {
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
                Outcome::Success(PublicKeyBytesAuth {
                    auth,
                    data: Vec::from(bytes),
                    phantom_perm: PhantomData,
                    phantom_provider: PhantomData,
                })
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
    > OpenApiFromData<'a> for PublicKeyBytesAuth<Perm, AuthInfo, PermProvider, PERM>
{
    fn request_body(
        gen: &mut OpenApiGenerator,
    ) -> rocket_okapi::Result<rocket_okapi::okapi::openapi3::RequestBody> {
        let schema = gen.json_schema::<Vec<u8>>();
        Ok(RequestBody {
            content: {
                let mut map = Map::new();
                map.insert(
                    "application/octet-stream".to_owned(),
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
