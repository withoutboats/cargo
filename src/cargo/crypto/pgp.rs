use serde::de;

use super::ed25519;
use super::pbp;
use super::{Sha256, Sha512};

#[derive(Deserialize)]
pub struct TrustedKeySet {
    #[serde(rename = "key")]
    keys: Vec<TrustedKey>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Privilege {
    Commit,
    Rotate,
}

impl TrustedKeySet {
    pub fn verify(&self, data: &[u8], signature: &pbp::PgpSig, privilege: Privilege)
        -> Result<bool, ed25519::SignatureError>
    {
        // NB: Both signatures and keys have a "fingerprint," a SHA-1 hash of
        // the public key used to identify which key created each signature.
        //
        // We don't *require* the signature's key to be correct; rather, we
        // use it as an optimization to avoid attempting verification multiple
        // times. However, if the fingerprint is wrong (representing a bug
        // somewhere else in the system), we attempt to verify against all
        // trusted keys.

        let fingerprint = signature.fingerprint();

        let matched_key = self.keys.iter().find(|&key| {
            key.privileged(privilege) && key.key.fingerprint() == fingerprint
        });

        if let Some(key) = matched_key {
            if verify(&key.key, &signature, data)? { return Ok(true) }
        }

        let other_keys = self.keys.iter().filter(|&key| {
            key.privileged(privilege) && Some(key) != matched_key
        });

        for key in other_keys {
            if verify(&key.key, &signature, data)? { return Ok(true) }
        }

        Ok(false)
    }
}

#[derive(Deserialize, Eq, PartialEq)]
struct TrustedKey {
    #[serde(deserialize_with = "deserialize_key")]
    key: pbp::PgpKey,
    #[serde(default, rename = "can-commit")]
    can_commit: bool,
    #[serde(default, rename = "can-rotate")]
    can_rotate: bool,
}

impl TrustedKey {
    fn privileged(&self, privilege: Privilege) -> bool {
        match privilege {
            Privilege::Commit   => self.can_commit,
            Privilege::Rotate   => self.can_rotate,
        }
    }
}

fn verify(key: &pbp::PgpKey, sig: &pbp::PgpSig, data: &[u8]) -> Result<bool, ed25519::SignatureError>
{
    Ok(sig.verify_dalek::<Sha256, Sha512, _>(&key.to_dalek()?, |h| h.update(data)))
}

fn deserialize_key<'de, D: de::Deserializer<'de>>(deserializer: D)
    -> Result<pbp::PgpKey, D::Error>
{
    let s = <String as de::Deserialize>::deserialize(deserializer)?;
    s.parse().map_err(::serde::de::Error::custom)
}
