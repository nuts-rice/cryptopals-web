use anyhow::{Error, Result};

use digest::*;
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use session_types::*;
use sha1::Sha1;
use std::fmt::*;

use tracing::debug;

#[derive(Default, Debug)]
pub struct DH {
    pub g: u32,
    pub p: BigUint,
}
#[derive(Default, Debug)]
pub struct SecretSharedPair {
    pub a: BigUint,
    pub b: BigUint,
}

impl DH {
    pub fn new(p: BigUint, g: u32) -> Self {
        DH { p: (p), g: (g) }
    }
    // pub fn new() -> Self {
    //     let p_hex = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
    //              020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
    //              4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
    //              ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
    //              98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
    //              9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    //     let p = BigUint::parse_bytes(p_hex, 16).unwrap();
    //     DH {
    //         g: BigUint::new(vec![2]),
    //         p: (p),
    //     }
    pub fn diffie_hellman(&self) -> Result<SecretSharedPair, Error> {
        let mut rng = rand::thread_rng();
        let k_priv_a: BigUint = rng.gen_biguint(1000) % &self.p;
        let k_priv_b: BigUint = rng.gen_biguint(1000) % &self.p;
        let k_pub_a: BigUint = BigUint::from(self.g).modpow(&k_priv_a, &self.p);
        let k_pub_b: BigUint = BigUint::from(self.g).modpow(&k_priv_b, &self.p);
        let k_session_1 = k_pub_b.modpow(&k_priv_a, &self.p);
        let k_session_2 = k_pub_a.modpow(&k_priv_b, &self.p);
        assert_eq!(k_session_1, k_session_2);
        let shared_pair = SecretSharedPair {
            a: k_session_1,
            b: k_session_2,
        };

        Ok(shared_pair)
    }
}

mod handshake {
    use super::*;
    use clap::Parser;

    type server = Recv<DH, Send<Key, Eps>>;
    type client = <server as HasDual>::Dual;

    #[derive(Parser, Debug)]
    struct Args {
        #[arg(short, long, default_value_t = 3)]
        prime: u32,
        #[arg(short, long, default_value_t = 1)]
        generator: u32,
    }

    pub type Key = Box<Vec<u8>>;
    fn secret_to_key(s: &[u8]) -> Key {
        Box::new(Sha1::digest(s)[0..16].to_vec())
    }

    pub fn handshake(_dh: DH, channel: Chan<(), server>) {
        let (channel, dh) = channel.recv();
        let _dh = dh.diffie_hellman().unwrap();
        let B = _dh.b;

        let tx = secret_to_key(&B.to_bytes_be());
        debug!("server sending: {:#?}", tx);
        let c = channel.send(tx);
        c.close()
    }

    fn session() {
        unimplemented!()
    }

    pub fn handshake_cli(_c: Chan<(), Rec<client>>) {
        let args = Args::parse();
        debug!("p: {}, g: {}", args.prime, args.generator);

        // let prime =
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[traced_test]
    fn diffie_hellman_test() {
        let _dh = DH::new(BigUint::from(31u32), 3);
        let shared_scret = _dh.diffie_hellman().unwrap();
        info!("shared secret is {:#?}", shared_scret);
        assert_range!(BigUint::from(1u32)..BigUint::from(31u32), shared_scret.a);
    }

    #[test]
    #[traced_test]
    fn handshake_test() {
        let dh = DH::new(BigUint::from(31u32), 3);
        info!(
            "spawning diffie hellman echo bot with diffie hellman of {:#?} ",
            dh
        );
        let (c1, c2) = session_channel();
        spawn(move || handshake::handshake(dh, c1));
        // let (c, _n) = c2.send(Box<Vec<>>);
        // c.close();
    }
}
