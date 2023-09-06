use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
};
use rocket_okapi::okapi::openapi3::{
    Object, SecurityRequirement, SecurityScheme, SecuritySchemeData,
};
use rocket_okapi::{
    gen::OpenApiGenerator,
    request::{OpenApiFromRequest, RequestHeaderInput},
};
use std::marker::PhantomData;

use crate::{
    error::Error,
    types::{PermissionCheck, Token, TokenAuth},
    HasTokenAuth,
};

#[rocket::async_trait]
impl<
        'a,
        const PERM: u8,
        Perm: TryFrom<u8>,
        AuthInfo,
        PermProvider: HasTokenAuth<Perm, AuthInfo> + Send + Sync + 'static,
    > FromRequest<'a> for TokenAuth<Perm, AuthInfo, PermProvider, PERM>
{
    type Error = crate::error::Error;
    async fn from_request(
        request: &'a rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        match request.headers().get_one("Authorization") {
            Some(token) => {
                let striped_token = token.strip_prefix("Bearer ").unwrap_or(token).to_owned();
                let pp = request.rocket().state::<PermProvider>();
                if pp.is_none() {
                    return Outcome::Failure((Status::Unauthorized, Error::NoProvider));
                };
                let pp = pp.unwrap();
                match pp.check_permission(Token(striped_token), PERM).await {
                    PermissionCheck::Success(auth) => Outcome::Success(TokenAuth {
                        auth,
                        phantom_perm: PhantomData,
                        phantom_provider: PhantomData,
                    }),
                    PermissionCheck::Error(e) => Outcome::Failure((
                        Status::InternalServerError,
                        Error::PermissionCheckError(e),
                    )),
                    PermissionCheck::Unauthorized => {
                        Outcome::Failure((Status::Unauthorized, Error::Unauthorized))
                    }
                    PermissionCheck::PermissionDenied => {
                        Outcome::Failure((Status::Forbidden, Error::Forbidden))
                    }
                }
            }
            None => Outcome::Failure((Status::Unauthorized, Error::MissingAuthHeader)),
        }
    }
}

impl<
        'a,
        const PERM: u8,
        Perm: TryFrom<u8> + Send,
        AuthInfo,
        PermProvider: HasTokenAuth<Perm, AuthInfo> + Send + Sync + 'static,
    > OpenApiFromRequest<'a> for TokenAuth<Perm, AuthInfo, PermProvider, PERM>
{
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // Setup global requirement for Security scheme
        let security_scheme = SecurityScheme {
            description: Some(
                "Requires an Bearer token to access, token is: `mytoken`.".to_owned(),
            ),
            // Setup data requirements.
            // In this case the header `Authorization: mytoken` needs to be set.
            data: SecuritySchemeData::Http {
                scheme: "bearer".to_owned(), // `basic`, `digest`, ...
                // Just gives use a hint to the format used
                bearer_format: Some("bearer".to_owned()),
            },
            extensions: Object::default(),
        };
        // Add the requirement for this route/endpoint
        // This can change between routes.
        let mut security_req = SecurityRequirement::new();
        // Each security requirement needs to be met before access is allowed.
        security_req.insert("TokenAuth".to_owned(), Vec::new());
        // These vvvvvvv-----^^^^^^^^ values need to match exactly!
        Ok(RequestHeaderInput::Security(
            "TokenAuth".to_owned(),
            security_scheme,
            security_req,
        ))
    }
}
