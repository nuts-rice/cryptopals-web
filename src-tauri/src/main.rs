// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cryptopals_web::diffie_hellman::*;
use num_bigint::BigUint;
use std::iter::repeat;
use tracing::info;
// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn srp_repl_demo() -> Result<String, ()> {
    unimplemented!()
}

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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![generate_dh, dh_mitm_attack_demo])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
