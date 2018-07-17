use std::io::Write;

use super::crypto_hash::{Algorithm, Hasher};
use super::digest::{Input, BlockInput, FixedOutput};
use super::generic_array::GenericArray;

pub struct Sha256(Hasher);

impl Sha256 {
    pub fn new() -> Sha256 {
        let hasher = Hasher::new(Algorithm::SHA256);
        Sha256(hasher)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let _ = self.0.write_all(bytes);
    }

    pub fn finish(&mut self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        let data = self.0.finish();
        ret.copy_from_slice(&data[..]);
        ret
    }
}

impl Default for Sha256 {
    fn default() -> Self { Sha256::new() }
}

impl Input for Sha256 {
    fn process(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

impl BlockInput for Sha256 {
    type BlockSize = super::typenum::U64;
}

impl FixedOutput for Sha256 {
    type OutputSize = super::typenum::U32;
    fn fixed_result(mut self) -> GenericArray<u8, super::typenum::U32> {
        self.finish().into()
    }
}
