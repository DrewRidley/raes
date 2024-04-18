// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::fs::File;

use crate::shared::key_expansion;

pub fn decrypt(ciphertext: File, key: &[u8; 32], path: String) -> File {
    let round_keys = key_expansion(*key);
    perform_rounds(&round_keys);
    File::create(path).unwrap()
}

// this function will perform the operations of a decryption round
fn perform_rounds(round_keys: &[u32; 8]) {
    add_round_key(round_keys[round_keys.len() - 1]); // add last round key

    for i in (1..14).rev() {
        // reversed so round keys are inserted in reverse
        inverse_shift_rows();
        inverse_sub_bytes();
        add_round_key(round_keys[i]);
        inverse_mix_columns();
    }

    inverse_shift_rows();
    inverse_sub_bytes();
    add_round_key(round_keys[0]);
}

#[cfg(test)]
mod test {}
