#![no_std]
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
pub struct Information<'a> {
    pub nonce: [u8; 12],
    pub key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: &'a[u8],
}
