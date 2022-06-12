use std::fs;

use methods::{MULTIPLY_ID, MULTIPLY_PATH};
use risc0_zkvm_host::Prover;
use risc0_zkvm_serde::{from_slice, to_vec};
use tempfile::tempdir;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
pub struct Information <'a> {
    pub nonce: [u8; 12],
    pub key: [u8; 32],
    pub ciphertext:&'a [u8],
}
fn main() {
    let b = b"unique nonce";
    let c = b"an example very very secret key.";
    let key = Key::from_slice(c);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b);
    let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
    .expect("encryption failure!");
    println!("Ciphertext {:?}", &ciphertext);
    let temp_dir = tempdir().unwrap();
    let id_path = temp_dir
        .path()
        .join("multiply.id")
        .to_str()
        .unwrap()
        .to_string();
    fs::write(&id_path, MULTIPLY_ID).unwrap();
    let mut prover = Prover::new(&MULTIPLY_PATH, &id_path).unwrap();
    let input = Information{
        nonce: *b,
        key: *c,
        ciphertext:&ciphertext,
    };
    // I am sure the problem in lifetime (for instance, in key field I tranfer array called 'c' and recieve the same array in the guest environment as in the host,
    // but when I tried to tranfer array called 'c' in the ciphertext field, I received different array
    let vec = risc0_zkvm_serde::to_vec(&input).unwrap();
    prover.add_input(vec.as_slice());
    println!("{:?}", &input.ciphertext);

    let receipt = prover.run().unwrap();

    let c = receipt.get_seal().unwrap();
    let c: Result<bool, _> = from_slice(c);
    let c = c.unwrap();
    println!("{:?}", c);
}
