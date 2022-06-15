#![no_main]
#![no_std]

use risc0_zkvm_guest::{env, sha};

risc0_zkvm_guest::entry!(main);
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use core::str::from_utf8;
use checker_core::Information;
pub fn main() {
   let info: Information = env::read();
    let key = Key::from_slice(&info.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&info.nonce);
    let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
    .expect("encryption failure!");
    let plaintext = cipher.decrypt(nonce, info.ciphertext.as_ref())
    .expect("decryption failure!");
    env::commit(&(&plaintext == b"plaintext message"));
    
}
