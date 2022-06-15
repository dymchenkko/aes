use std::fs;
use methods::{DECRYPT_ID, DECRYPT_PATH};
use std::time::Instant;
use risc0_zkvm_host::Prover;
use risc0_zkvm_serde::{from_slice};
use tempfile::tempdir;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use checker_core::Information;
fn main() {
    let nonce_bytes = b"uniiue nonce";
    let secret_key_bytes = b"an example very very secret key.";
    let plaintext_bytes = b"plaintext message";
    let key = Key::from_slice(secret_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext_bytes.as_ref())
    .expect("encryption failure!");
    let temp_dir = tempdir().unwrap();
    let id_path = temp_dir
        .path()
        .join("decrypt.id")
        .to_str()
        .unwrap()
        .to_string();
    fs::write(&id_path, DECRYPT_ID).unwrap();
    let mut prover = Prover::new(&DECRYPT_PATH, &id_path).unwrap();
    let input = Information{
        nonce: *nonce_bytes,
        key: *secret_key_bytes,
        ciphertext:&ciphertext,
    };
   let vec = risc0_zkvm_serde::to_vec(&input).unwrap();
    prover.add_input(vec.as_slice());
    let now = Instant::now();
    let receipt = prover.run().unwrap();
    let elapsed = now.elapsed();
    println!("Elapsed: {:.3?}", elapsed);
    let c = receipt.get_seal().unwrap();
    let c: Result<bool, _> = from_slice(c);
    let c = c.unwrap();
    println!(" Result is {:?}", c);
}

