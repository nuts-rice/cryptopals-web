// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cryptopals_web::diffie_hellman::*;
use num_bigint::BigUint;
// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn generate_dh(prime: String, generator: String) -> Result<String, ()> {
    let prime: u32 = prime.parse().unwrap();
    let generator: u32 = generator.parse().unwrap();
    let shared_secret: BigUint = BigUint::from(0u32);
    let mut _dh = DH::new(BigUint::from(prime), generator);
    let shared = _dh.diffie_hellman().unwrap();
    Ok(format!(
        "diffie hellman is: {:?}, shared secret for Alice is {}, shared secret for Bob is {}",
        shared, shared.a, shared.b
    ))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet, generate_dh])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
