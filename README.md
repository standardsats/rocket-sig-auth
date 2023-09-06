# rocket-sig-auth
Authentication library for Rocket. Supports Bearer Auth and secp256k1 Public key auth.

# Permission and aliases

Typically permissions are simple enums.
The library passes permission as a `const u8` type parameter to permission provider to check.
Because of that, permissions are supposed to have `TryFrom` trait.

To efficiently use type aliases, `Permission` must have 
```rust 
pub const fn as_u8(p: Permission) -> u8
```

const is important, otherwise the function can't be used in types.

Requires 
```rust
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(adt_const_params)]
```

# Permission provider

We do not specify the container for actual permission provider, so the traits must me implemented for a type, which implements `Send` and `Copy`

For example, `sqlx` Postgres `Pool` must be wraped in an `Arc` to pass to the rocket state.
The library doesn't know about the `Arc` and rust doesn't allow implementing traits for `Arc` in different crates, so the user has to create a wrapper:
```rust 
pub struct AuthPool(pub Pool)
```

and implement authorization traits for `AuthPool`

In a different example, `rusqlite` `Connection` has to be wrapped into `Arc<Mutex<Connection>>`. Same idea: wrap the resulting container into a newtype and implent traits for it.

# Nonce handling

Authorization scheme uses UTC timestamps (in seconds!) as a nonce.
The library doesn't cache nonces (yet?) and implements stateless authorization scheme.
To limit a possibility of repeating attacks nonces have expiration. Permission provider gives `nonce_timeout`. If current UTC timestamp on the server differs from provided nonce timestamp for more than `nonce_timeout` seconds, the request is invalid and no further checks are made.