// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cryptopals_web::diffie_hellman::*;
use cryptopals_web::srp::srp_handshake::*;
pub(crate) use firestorm::profile_fn;

use num_bigint::BigUint;
use std::iter::repeat;
use tracing::info;

enum EvilBehavior {
    DHTamper,
    BadConditionals,
}

#[tauri::command]
async fn srp_repl_demo(prime: String, user_email: String, user_pass: String) -> Result<String, ()> {
    profile_fn!(srp_repl_demo);
    let prime: u64 = prime.parse().unwrap();
    let secret = Secret {
        n: prime,
        g: 2u64,
        k: 3u64,
        email: user_email,
        password: user_pass,
    };
    let mut srvr_secret = Server_Secret {
        priv_b: [0u8, 2],
        server_proof: vec![0u8, 64],
    };
    let hash = gen_hash(&secret).unwrap();
    let mut pub_k: PubKeys = PubKeys {
        a: vec![0u8; 16],
        b: vec![0u8; 16],
    };
    server_session(hash, &mut pub_k, &mut srvr_secret);
    let client_ses = client_session(&secret, &mut pub_k);
    Ok(format!("User proof is {:?}", client_ses.unwrap()))
}

mod FunkyFiniteFields {
    use super::*;
    use subtle::ConstantTimeEq;
    pub const BRANCH_SECRET: u64 = 1234567890123456;
    struct FieldElement {
        limbs: usize,
        order: BigUint,
        modulus: BigUint,
        a2: usize,
        a4: usize,
        a6: usize,
    }

    //conditional assignment
    //refer to
    //https://research.nccgroup.com/2022/06/15/public-report-threshold-ecdsa-cryptography-review/ and
    //https://github.com/dfinity/ic/commit/34703fad074f5bb53142b2cf5f569c5c66c6c3b1#diff-1b547352196f5d4ae84d7793a304d5d780d757dfd0959465c4e5fde996608a54
    #[tauri::command]
    async fn ct_timing_demo() -> Result<String, ()> {
        if cfg!(feature = "mal") {
            todo!()
            // assign_on_secret(val, naughty_cmp)
        } else {
            let _cmp = subtle::Choice::from(1u8);
            todo!()
            // assign_on_subtle(val, cmp)
        }

        Ok(format!(""))
    }

    //happy choice for conditionally assigning using subtle::choice and subtle::constanttimeeq
    pub fn assign_on_subtle(target: u64, _assign: subtle::Choice) {
        let mut cmp = subtle::Choice::from(1u8);
        for i in 0..=999 {
            cmp &= BRANCH_SECRET.to_be_bytes()[i].ct_eq(&target.to_be_bytes()[i])
        }
        unimplemented!()
    }

    //evil naughty choice for bad boys!
    pub fn assign_on_secret(target: u64, _assign: bool) {
        let mut cmp = 0;
        for i in 0..=999 {
            cmp |= BRANCH_SECRET.to_be_bytes()[i] ^ target.to_be_bytes()[i]
        }
    }

    // pub fn random_fe ()  -> FieldElement {
    //     let mut rng = rand::thread_rng();
    //     let mut buf = vec![0u8; ]
    // }
}
//TODO: Implement Evil choice for this
#[tauri::command]
async fn dh_mitm_attack_demo(prime: String, generator: String) -> Result<String, ()> {
    let prime: u32 = prime.parse().unwrap();
    let generator: u32 = generator.parse().unwrap();
    //TODO: test and return n_predictions for key in diffie_hellman
    let n_prediction: f64 = 0.0;
    let mut _dh = DH::new(prime, generator);
    //TODO: evil dh session for client according to cryptopals
    let msg: Vec<u8> = repeat(0u8).take(64).collect();
    info!("decrypted message is {:?}", msg);
    info!("predictability of key using {}: {:?}", prime, n_prediction);
    Ok(format!("{:?}", msg))
}

#[tauri::command]
async fn generate_dh(prime: String, generator: String) -> Result<String, ()> {
    let prime: u32 = prime.parse().unwrap();
    let generator: u32 = generator.parse().unwrap();
    let _shared_secret: BigUint = BigUint::from(0u32);
    let mut _dh = DH::new(prime, generator);
    let shared = _dh.diffie_hellman().unwrap();
    Ok(format!(
        "diffie hellman prime: {}, diffie hellman generator: {}, shared secret for Alice is {}, shared secret for Bob is {}",
        prime, generator, shared.a, shared.b
    ))
}
//TODO: figure out flamegraph okay?

macro_rules! evil {
    ($var:ident) => {
        if cfg!(feature = "mal") {
            "😈😈😈".to_string()
        } else {
            $var
        }
    };
}
fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            generate_dh,
            dh_mitm_attack_demo,
            srp_repl_demo
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
