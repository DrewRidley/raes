// This file holds the code to decrypt using our implementation of the AES algorithm.

use crate::shared::{
    add_round_key, expand_block_to_state, flatten_state_to_block, inverse_mix_columns, inverse_shift_rows, inverse_sub_bytes, key_expansion
};


pub fn decrypt_block(data: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_key = key_expansion(*key);
    let mut output: [u8; 16] = [0; 16];
    output.copy_from_slice(data);
    let mut state = expand_block_to_state(output);

    // Perform the decryption rounds
    //perform_inverse_rounds(&mut state, &round_key);
    output = flatten_state_to_block(state);

    return output;
}

