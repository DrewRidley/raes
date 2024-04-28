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

fn perform_inverse_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 60]) {
    // Start with the final round key (after all rounds)
    *state = add_round_key(
        *state,
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ],
    );

    // Inverse final round (no mix columns)
    inverse_sub_bytes(state);
    inverse_shift_rows(state);

    // Do the rest of the rounds in reverse order
    for i in (1..14).rev() {
        *state = add_round_key(
            *state,
            [
                round_keys[4 * i],
                round_keys[4 * i + 1],
                round_keys[4 * i + 2],
                round_keys[4 * i + 3],
            ],
        );
        inverse_mix_columns(state);
        inverse_sub_bytes(state);
        inverse_shift_rows(state);
    }

    // Last AddRoundKey with the first round key
    *state = add_round_key(
        *state,
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
    );
}