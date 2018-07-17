extern crate ed25519_dalek as ed25519;
extern crate crypto_hash;
extern crate digest;
extern crate generic_array;
extern crate pbp;
extern crate typenum;

mod sha256;
mod sha512;
mod pgp;

pub use self::sha256::Sha256;
pub use self::sha512::Sha512;
pub use self::pgp::{Signature, TrustedKeySet};
