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
    nonce: Vec<u8>,
}

impl Encryptor {
    pub fn new() -> Encryptor {
        let cleartxt = (fs::read(Path::new("../data/25.txt"))).unwrap();
        let mut rng = OsRng::default();
        let mut key = [0u8; 16];
        rng.fill(&mut key[..]);
        let mut _nonce = [0u8; 16];
        rng.fill(&mut _nonce[..]);
        let mut cipher = aes::ctr(KeySize::KeySize128, &key, &_nonce);
        let mut output_buffer: Vec<u8> = repeat(0u8).take(cleartxt.len()).collect();
        let ciphertxt = cipher.process(cleartxt.as_slice(), &mut output_buffer[..]);
        Encryptor {
            cleartext: cleartxt,
            key: key.to_vec(),
            ciphertext: output_buffer,
            nonce: _nonce.to_vec(),
        }
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn aes_oracle(&self, canidate_cleartext: &[u8]) -> Result<(), String> {
        if (&self.cleartext[..]).eq(canidate_cleartext) {
            Ok(())
        } else {
            Err(String::from("Not the same"))
        }
    }

    pub fn edit(&self, offset: usize, newtext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut cleartxt = self.cleartext.clone();
        let end = offset + newtext.len();
        let mut output_buffer: Vec<u8> = repeat(0u8).take(end).collect();
        cleartxt[offset..end].copy_from_slice(newtext);
        let mut cipher = aes::ctr(KeySize::KeySize128, &self.key, &self.nonce);
        let ciphertxt = cipher.process(cleartxt.as_slice(), &mut output_buffer[..]);
        Ok(output_buffer)
    }
}

pub trait Oracle {
    // fn new(cleartext: Vec<u8>, ) -> Self;
    // fn check_oracle(&self) -> Result<(), String>;
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, ()>;
}

struct Common {
    cleartext: Vec<u8>,
    keysize: KeySize,
    key: Vec<u8>,
    nonce: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

pub struct Oracle26 {
    common: Common,
}

impl Oracle for Common {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!()
    }
}

impl Oracle26 {
    fn new() -> Result<Self, ()> {
        let mut rng = OsRng::default();
        let mut key = [0u8; 16];
        rng.fill(&mut key[..]);
        let mut _nonce = [0u8; 16];
        rng.fill(&mut _nonce[..]);
        unimplemented!()
    }
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!()
        // let mut rng = OsRng::default();
        // let mut key = [0u8; 16];
        // rng.fill(&mut key[..]);
        // let mut _nonce = [0u8; 16];
        // rng.fill(&mut _nonce[..]);
    }

    fn check_oracle(&self, canidate_cleartext: Vec<u8>) -> Result<(), String> {
        if (&self.common.cleartext[..]).eq(&canidate_cleartext) {
            Ok(())
        } else {
            Err(String::from("Not the same"))
        }
    }
}
