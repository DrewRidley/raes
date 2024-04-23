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

fn inverse_shift_rows(state: &mut [[u8; 4]; 4]) {
    
    // Second row shifts right by 1
    let temp = state[1][3];
    for i in (1..4).rev() {
        state[1][i] = state[1][i - 1];
    }
    state[1][0] = temp;
    
    let temp1 = state[2][3];
    let temp2 = state[2][2];
    state[2][2] = state[2][1];
    state[2][3] = state[2][0];
    state[2][0] = temp2;
    state[2][1] = temp1;
    
    let temp = state[3][0];
    for i in 0..3 {
        state[3][i] = state[3][i + 1];
    }
    state[3][3] = temp;
}


#[cfg(test)]
mod test {}
