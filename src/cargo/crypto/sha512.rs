use std::io::Write;

use super::crypto_hash::{Algorithm, Hasher};
use super::digest::{Input, BlockInput, FixedOutput};
use super::generic_array::GenericArray;

pub struct Sha512(Hasher);

impl Sha512 {
    pub fn new() -> Sha512 {
        let hasher = Hasher::new(Algorithm::SHA512);
        Sha512(hasher)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let _ = self.0.write_all(bytes);
    }

    pub fn finish(&mut self) -> [u8; 64] {
        let mut ret = [0u8; 64];
        let data = self.0.finish();
        ret.copy_from_slice(&data[..]);
        ret
    }
}

impl Default for Sha512 {
    fn default() -> Self { Sha512::new() }
}

impl Input for Sha512 {
    fn process(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

impl BlockInput for Sha512 {
    type BlockSize = super::typenum::U128;
}

impl FixedOutput for Sha512 {
    type OutputSize = super::typenum::U64;
    fn fixed_result(mut self) -> GenericArray<u8, super::typenum::U64> {
        *GenericArray::from_slice(&self.finish())
    }
}
