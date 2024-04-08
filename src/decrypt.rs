// This file holds the code to decrypt using our implementation of the AES algorithm. 

use std::fs::File;

pub fn decrypt<const N: usize>(ciphertext: File, key: &[u8; N]) -> File {
    let round_keys = create_round_keys(*key);
    perform_rounds(round_keys);
}

fn create_round_keys<const N: usize>(key: [u8; N]) -> Vec<[u8; N]> {
    
}

fn perform_rounds<const N: usize>(round_keys: Vec<[u8; N]>) {
    add_round_key();
    inverse_mix_columns();
    shift_rows();
    inverse_sub_byte();
}