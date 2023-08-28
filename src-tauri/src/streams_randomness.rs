use std::fs::{self, File};
use std::iter::repeat;
use std::path::Path;

use crypto::aes::{self, KeySize};

use rand::{rngs::OsRng, Rng};
use rustc_serialize::base64::{ToBase64, STANDARD};
use rustc_serialize::hex::ToHex;
#[derive(Debug, PartialEq)]
pub struct Encryptor {
    cleartext: Vec<u8>,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Encryptor {
    pub fn new() -> Encryptor {
        let cleartxt = (fs::read(Path::new("../data/25.txt"))).unwrap();
        let mut rng = OsRng::default();
        let mut key = [0u8; 16];
        rng.fill(&mut key[..]);
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce[..]);
        let mut cipher = aes::ctr(KeySize::KeySize128, &key, &nonce);
        let mut output_buffer: Vec<u8> = repeat(0u8).take(cleartxt.len()).collect();
        let ciphertxt = cipher.process(cleartxt.as_slice(), &mut output_buffer[..]);
        Encryptor {
            cleartext: cleartxt,
            key: key.to_vec(),
            ciphertext: output_buffer,
        }
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn edit(&self, offset: usize, newtext: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!()
    }
}
