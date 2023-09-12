use std::{error::Error, str::FromStr, sync::Arc};

use async_trait::async_trait;
use rocket::{
    get, post,
    response::Redirect,
    routes,
    serde::json::Json,
    serde::Deserialize,
    tokio::{self, sync::Mutex},
    FromFormField, State,
};
use rocket_okapi::{
    openapi, openapi_get_routes,
    swagger_ui::{make_swagger_ui, SwaggerUIConfig},
    JsonSchema,
};
use rocket_sig_auth::{types::*, HasPublicKeyAuth, HasTokenAuth};
use rusqlite::{params, Connection};
use serde::Serialize;

pub type DbMux = Arc<Mutex<Db>>;
pub struct AuthDb(pub DbMux);

pub struct Db {
    pub conn: Connection,
    pub domain: String,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromFormField, JsonSchema)]
pub enum Role {
    Admin,
    User,
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Admin" => Ok(Role::Admin),
            "User" => Ok(Role::User),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum UserPermission {
    Read,
    Write,
    Sudo,
}

impl UserPermission {
    pub const fn as_u8(perm: UserPermission) -> u8 {
        match perm {
            UserPermission::Read => 0,
            UserPermission::Write => 1,
            UserPermission::Sudo => 2,
        }
    }
}

impl TryFrom<u8> for UserPermission {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UserPermission::Read),
            1 => Ok(UserPermission::Write),
            2 => Ok(UserPermission::Sudo),
            _ => Err(()),
        }
    }
}

pub struct User {
    pub id: i32,
    pub role: Role,
    pub token: Option<String>,
    pub public_key: Option<String>,
}

pub fn init_db(domain: String) -> Result<Db, rusqlite::Error> {
    let conn = Connection::open_in_memory()?;
    conn.execute(
        "create table users(
        id integer primary key,
        role text not null,
        token text unique,
        public_key text unique
    )",
        [],
    )?;
    Ok(Db {
        conn,
        domain,
        timeout: 10,
    })
}

type AuthInfo = i32;

impl Db {
    fn insert_user(
        &self,
        role: Role,
        token: Option<String>,
        public_key: Option<String>,
    ) -> Result<(), rusqlite::Error> {
        let role_str = format!("{:?}", role);
        self.conn.execute(
            "insert into users(role, token, public_key) values (?1, ?2, ?3)",
            params![role_str, token, public_key],
        )?;
        Ok(())
    }

    fn get_user_by_token(&self, token: &str) -> Result<Option<User>, rusqlite::Error> {
        self.conn.query_row(
            "select * from users where token = ?1",
            params![token],
            |row| {
                let id = row.get(0)?;
                let role: String = row.get(1)?;
                let token = row.get(2)?;
                let public_key = row.get(3)?;
                Ok(Role::from_str(&role).ok().map(|role| User {
                    id,
                    role,
                    token,
                    public_key,
                }))
            },
        )
    }

    fn get_user_by_public_key(&self, public_key: &str) -> Result<Option<User>, rusqlite::Error> {
        self.conn.query_row(
            "select * from users where public_key = ?1",
            params![public_key],
            |row| {
                let id = row.get(0)?;
                let role: String = row.get(1)?;
                let token = row.get(2)?;
                let public_key = row.get(3)?;
                Ok(Role::from_str(&role).ok().map(|role| User {
                    id,
                    role,
                    token,
                    public_key,
                }))
            },
        )
    }
}

#[async_trait]
impl HasTokenAuth<UserPermission, AuthInfo> for AuthDb {
    async fn check_permission(
        &self,
        token: rocket_sig_auth::types::Token,
        perm: u8,
    ) -> rocket_sig_auth::types::PermissionCheck<AuthInfo> {
        let perm = perm.try_into();
        if perm.is_err() {
            return PermissionCheck::Error("Failed to parse permission".to_string());
        };
        let perm = perm.unwrap();
        match self.0.lock().await.get_user_by_token(&token.0) {
            Ok(Some(user)) => match (user.role, perm) {
                (Role::Admin, _) => PermissionCheck::Success(user.id),
                (Role::User, UserPermission::Sudo) => PermissionCheck::PermissionDenied,
                _ => PermissionCheck::Success(user.id),
            },
            _ => PermissionCheck::Unauthorized,
        }
    }
}

#[async_trait]
impl HasPublicKeyAuth<UserPermission, AuthInfo> for AuthDb {
    async fn check_permission(
        &self,
        public_key: rocket_sig_auth::types::PublicKey,
        perm: u8,
    ) -> PermissionCheck<AuthInfo> {
        let perm = perm.try_into();
        if perm.is_err() {
            return PermissionCheck::Error("Failed to parse permission".to_string());
        };
        let perm = perm.unwrap();
        match self.0.lock().await.get_user_by_public_key(&public_key.0) {
            Ok(Some(user)) => match (user.role, perm) {
                (Role::Admin, _) => PermissionCheck::Success(user.id),
                (Role::User, UserPermission::Sudo) => PermissionCheck::PermissionDenied,
                _ => PermissionCheck::Success(user.id),
            },
            _ => PermissionCheck::Unauthorized,
        }
    }

    async fn get_domain(&self) -> String {
        let db = self.0.lock().await;
        db.domain.clone()
    }

    async fn get_nonce_timeout(&self) -> u64 {
        self.0.lock().await.timeout
    }
}

#[async_trait]
impl HasPublicKeyAuth<u8, String> for AuthDb {
    async fn check_permission(
        &self,
        public_key: rocket_sig_auth::types::PublicKey,
        _: u8,
    ) -> PermissionCheck<String> {
        PermissionCheck::Success(public_key.0)
    }

    async fn get_domain(&self) -> String {
        let db = self.0.lock().await;
        db.domain.clone()
    }

    async fn get_nonce_timeout(&self) -> u64 {
        self.0.lock().await.timeout
    }
}

#[openapi(tag = "example")]
#[get("/unauth")]
pub async fn unauth_endpoint() -> Json<String> {
    Json("Unauth handle".to_string())
}

#[openapi(tag = "example")]
#[get("/register/token?<token>&<role>")]
pub async fn unauth_register_endpoint(
    db: &State<DbMux>,
    token: String,
    role: Role,
) -> Json<String> {
    if let Err(e) = db.lock().await.insert_user(role, Some(token), None) {
        Json(e.to_string())
    } else {
        Json("Success!".to_string())
    }
}

type UnauthSignature<T> = PublicKeyAuth<u8, String, AuthDb, 0, T>;
type AuthSignature<const PERM: u8, T> = PublicKeyAuth<UserPermission, AuthInfo, AuthDb, PERM, T>;
type AuthToken<const PERM: u8> = TokenAuth<UserPermission, AuthInfo, AuthDb, PERM>;
type AuthCombined<const PERM: u8, T> = CombinedAuth<UserPermission, AuthInfo, AuthDb, PERM, T>;

#[openapi(tag = "example")]
#[post("/register/publickey", data = "<req>")]
pub async fn pkey_register_endpoint(db: &State<DbMux>, req: UnauthSignature<Role>) -> Json<String> {
    if let Err(e) = db.lock().await.insert_user(req.data, None, Some(req.auth)) {
        Json(e.to_string())
    } else {
        Json("Success!".to_string())
    }
}

#[openapi(tag = "example")]
#[get("/token/read")]
pub async fn token_read(auth: AuthToken<0>) -> Json<String> {
    Json(auth.auth.to_string())
}

#[openapi(tag = "example")]
#[get("/token/write")]
pub async fn token_write(auth: AuthToken<1>) -> Json<String> {
    Json(auth.auth.to_string())
}

#[openapi(tag = "example")]
#[get("/token/sudo")]
pub async fn token_sudo(auth: AuthToken<2>) -> Json<String> {
    Json(auth.auth.to_string())
}

#[openapi(tag = "example")]
#[post("/signature/read", data = "<req>")]
pub async fn signature_read(req: AuthSignature<0, String>) -> Json<String> {
    log::info!("User id {}", req.auth);
    Json(req.data.to_string())
}

#[openapi(tag = "example")]
#[post("/signature/write", data = "<req>")]
pub async fn signature_write(req: AuthSignature<1, String>) -> Json<String> {
    log::info!("User id {}", req.auth);
    Json(req.data.to_string())
}

#[openapi(tag = "example")]
#[post("/signature/sudo", data = "<req>")]
pub async fn signature_sudo(req: AuthSignature<2, String>) -> Json<String> {
    log::info!("User id {}", req.auth);
    Json(req.data.to_string())
}

#[openapi(tag = "example")]
#[post("/combined/read", data = "<req>")]
pub async fn combined_read(req: AuthCombined<0, String>) -> Json<String> {
    log::info!("User id {}", req.auth);
    Json(req.data.to_string())
}

#[openapi(tag = "example")]
#[post("/combined/write", data = "<req>")]
pub async fn combined_write(req: AuthCombined<1, String>) -> Json<String> {
    log::info!("User id {}", req.auth);
    Json(req.data.to_string())
}

#[openapi(tag = "example")]
#[post("/combined/sudo", data = "<req>")]
pub async fn combined_sudo(req: AuthCombined<2, String>) -> Json<String> {
    log::info!("User id {}", req.auth);
    Json(req.data.to_string())
}

#[get("/")]
pub async fn index() -> Redirect {
    Redirect::to("/swagger/index.html")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let db = init_db("http://127.0.0.1:8000".to_string())?;
    let db_mux = Arc::new(Mutex::new(db));
    let auth_db = AuthDb(db_mux.clone());

    let _ = rocket::build()
        .mount("/", routes![index])
        .mount(
            "/",
            openapi_get_routes![
                unauth_endpoint,
                unauth_register_endpoint,
                pkey_register_endpoint,
                token_read,
                token_write,
                token_sudo,
                signature_read,
                signature_write,
                signature_sudo,
                combined_read,
                combined_write,
                combined_sudo,
            ],
        )
        .mount(
            "/swagger",
            make_swagger_ui(&SwaggerUIConfig {
                url: "../openapi.json".to_owned(),
                ..Default::default()
            }),
        )
        .manage(db_mux)
        .manage(auth_db)
        .launch()
        .await
        .unwrap();
    Ok(())
}
