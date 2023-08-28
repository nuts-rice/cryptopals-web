use all_asserts::*;
use firestorm::{profile_fn, profile_method, profile_section};
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use session_types::*;
use tracing::*;
use tracing_test::traced_test;

use cryptopals_web::{diffie_hellman, handshake, srp_handshake, DH};
use std::thread::*;

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

        let pub_b = srp_handshake::server_session(hash.clone(), &mut pub_k, &mut srv_secret);
        let client_session = srp_handshake::client_session(&Scrt, &mut pub_k).unwrap();
        debug!("srvr secret is : {:#?}", srv_secret);
        debug!("pub keys are : {:#?}", pub_k);
        //TODO: fix verifier for this
        let server_v =
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
        let encrypted = handshake::secret_to_key(shared_scret.a.to_string().as_bytes());
        // debug!("dh is {:#?}, encrypted to {:#?}", _dh, encrypted);
    }

    #[test]
    #[traced_test]
    fn handshake_test() {
        let dh = DH::new(31, 3);
        info!(
            "spawning diffie hellman echo bot with diffie hellman of {:#?} ",
            dh
        );
        let (c1, c2) = session_channel();
        let handshake = spawn(move || handshake::srvr_handshake(&dh.clone(), "client msg", c1));
        handshake::client_session(&dh, "dummy msg", c2);
        // let handshake = spawn(move || handshake::handshake(&dh.clone(), c1));
        // handshake::client_session(&dh, c2);
        // let finalized_handshake = handshake.join().unwrap();
        //TODO: calculate predictability after evil handshake and assert
        // let (c, _n) = c2.send(Box<Vec<>>);
        // c.close();
    }
}
