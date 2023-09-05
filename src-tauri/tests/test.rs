use all_asserts::*;

use cryptopals_web::{handshake, srp_handshake, Encryptor, DH};
use num::BigUint;
use std::str::FromStr;
use tracing::*;
use tracing_test::traced_test;

#[cfg(tests)]
use super::*;
mod tests {
    use super::*;
    #[test]
    fn firestorm_test() {
        if firestorm::enabled() {
            firestorm::bench("./flames/", diffie_hellman_test).unwrap();
        }
    }

    #[test]
    #[traced_test]
    fn hash_test() {
        firestorm::profile_fn!(hash_test);
        let Scrt = srp_handshake::Secret {
            n: 31,
            g: 3,
            k: 2,
            email: String::from("jowbog@gmail.com"),
            password: String::from("sillyorange33342352"),
        };
        let mut srv_secret = srp_handshake::Server_Secret {
            priv_b: [0u8; 2],
            server_proof: vec![0u8; 16],
        };
        let hash = srp_handshake::gen_hash(&Scrt).unwrap();
        let mut pub_k: srp_handshake::PubKeys = srp_handshake::PubKeys {
            a: vec![0u8; 16],
            b: vec![0u8; 16],
        };

        let _pub_b = srp_handshake::server_session(hash.clone(), &mut pub_k, &mut srv_secret);
        let client_session = srp_handshake::client_session(&Scrt, &mut pub_k).unwrap();
        debug!("srvr secret is : {:#?}", srv_secret);
        debug!("pub keys are : {:#?}", pub_k);
        //TODO: fix verifier for this
        srp_handshake::server_verify(pub_k, &srv_secret.priv_b, hash, &Scrt, client_session);
        if firestorm::enabled() {
            firestorm::bench("./flames/", hash_test).unwrap();
        }
    }
    #[test]
    #[traced_test]
    fn diffie_hellman_test() {
        firestorm::profile_fn!(diffie_hellman_test);
        let _dh = DH::new(31, 3);
        let shared_scret = _dh.diffie_hellman().unwrap();
        info!("shared secret is {:#?}", shared_scret);
        assert_range!(BigUint::from(1u32)..BigUint::from(31u32), shared_scret.a);
    }

    #[test]
    #[traced_test]
    fn dh_utils_test() {
        let _dh = DH::new(31, 3);
        let shared_scret = _dh.diffie_hellman().unwrap();
        let _encrypted = handshake::secret_to_key(shared_scret.a.to_string().as_bytes());
        // debug!("dh is {:#?}, encrypted to {:#?}", _dh, encrypted);
    }

    #[test]
    fn test_challenge_43() {
        let p_hex = b"\
        800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1";
        let q_hex = b"f4f47f05794b256174bba6e9b396a7707e563c5b";
        let g_hex = b"\
        5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
        9fc95302291";
        let y_hex = b"\
        84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
        abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
        e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
        1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
        bb283e6633451e535c45513b2d33c99ea17";
        let m_hex = b"d2d0714f014a9784047eaeccf956520045c45265";

        let _p = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let _q = &BigUint::parse_bytes(q_hex, 16).unwrap();
        let _g = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let _y = &BigUint::parse_bytes(y_hex, 16).unwrap();
        let _m = &BigUint::parse_bytes(m_hex, 16).unwrap();

        let _r = &BigUint::from_str("548099063082341131477253921760299949438196259240").unwrap();
        let _s = &BigUint::from_str("857042759984254168557880549501802188789837994940").unwrap();
        let _privkey = b"0xf4f47f05794b256174bba6e9b396a7707e563c5b";
        // assert!((0..=65535).any(|k: u16| {
        //     let x = dsa::find_x(q, m, &BigUint::from(k), r, s);
        //     let mut hash = [0; 20];
        //     SHA1::default().hash(x.to_str_radix(16).as_bytes(), &mut hash);
        //     target_hash == hash
        // }));
    }

    //#[test]
    //#[traced_test]
    //fn handshake_test() {
    //    let dh = DH::new(31, 3);
    //    info!(
    //        "spawning diffie hellman echo bot with diffie hellman of {:#?} ",
    //        dh
    //    );
    //    let (c1, c2) = session_channel();
    //    let handshake = spawn(move || handshake::srvr_handshake(&dh.clone(), "client msg", c1));
    //    handshake::client_session(&dh, "dummy msg", c2);
    //    // let handshake = spawn(move || handshake::handshake(&dh.clone(), c1));
    //    // handshake::client_session(&dh, c2);
    //    // let finalized_handshake = handshake.join().unwrap();
    //    //TODO: calculate predictability after evil handshake and assert
    //    // let (c, _n) = c2.send(Box<Vec<>>);
    //    // c.close();
    //}

    #[test]
    #[traced_test]
    fn aes_ctr_test() {
        let encrypted = Encryptor::new();
        let ciphertxt = encrypted.get_ciphertext();
        let keystream = encrypted.edit(0, &vec![0; ciphertxt.len()]).unwrap();
        let xored: Vec<u8> = ciphertxt
            .iter()
            .zip(keystream.iter())
            .map(|(x, y)| *x ^ *y)
            .collect();
        debug!(
            "ciphertxt: {:?}, \n xored keystream: {:?}",
            ciphertxt, xored
        );
        let result = encrypted.aes_oracle(&xored).is_ok();
        assert_eq!(result, true);
    }
}
