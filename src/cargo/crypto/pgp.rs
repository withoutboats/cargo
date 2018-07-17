use std::str::FromStr;

use super::ed25519;
use super::pbp;
use super::{Sha256, Sha512};

pub struct Signature(pbp::PgpSig);

impl FromStr for Signature {
    type Err = pbp::PgpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Signature(s.parse()?))
    }
}

pub struct TrustedKeySet {
    keys: Vec<pbp::PgpKey>,
}

impl TrustedKeySet {
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool, ed25519::SignatureError>
    {
        // NB: Both signatures and keys have a "fingerprint," a SHA-1 hash of
        // the public key used to identify which key created each signature.
        //
        // We don't *require* the signature's key to be correct; rather, we
        // use it as an optimization to avoid attempting verification multiple
        // times. However, if the fingerprint is wrong (representing a bug
        // somewhere else in the system), we attempt to verify against all
        // trusted keys.

        let fingerprint = signature.0.fingerprint();
        let matched_key = self.keys.iter().find(|key| key.fingerprint() == fingerprint);

        if let Some(key) = matched_key {
            if verify(key, &signature.0, data)? { return Ok(true) }
        }

        for key in self.keys.iter().filter(|&k| Some(k) != matched_key) {
            if verify(key, &signature.0, data)? { return Ok(true) }
        }

        Ok(false)
    }
}

fn verify(key: &pbp::PgpKey, sig: &pbp::PgpSig, data: &[u8]) -> Result<bool, ed25519::SignatureError>
{
    Ok(sig.verify_dalek::<Sha256, Sha512, _>(&key.to_dalek()?, |h| h.update(data)))
}
