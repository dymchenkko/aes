#![no_main]
#![no_std]

use risc0_zkvm_guest::{env, sha};

risc0_zkvm_guest::entry!(main);
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use core::str::from_utf8;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Information<'a> {
    pub nonce: [u8; 12],
    pub key: [u8; 32],
    pub ciphertext: &'a[u8],
}
pub fn main() {
   let info: Information = env::read();
    let key = Key::from_slice(&info.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&info.nonce);
    let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
    .expect("encryption failure!");
    // this ciphertext I need to receive(the same as below), but receive : [116, 0, 0, 0, ...], so below I use just particular array, but I want to take dynamic one from info.ciphertext.
    let ciphertext = [116, 91, 46, 203, 180, 87, 176, 113, 174, 0, 131, 153, 181, 96, 241, 113, 248, 81, 116, 205, 254, 46, 225, 239, 29, 81, 154, 25, 46, 188, 244, 214, 232];
    //let plaintext = cipher.decrypt(nonce, info.ciphertext.as_ref()) - this I want to work for me, but info.ciphertext have wrong array
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
    .expect("decryption failure!");
    env::commit(&(&plaintext == b"plaintext message"));
    
}
