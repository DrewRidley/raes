// This file holds the code to decrypt using our implementation of the AES algorithm.

use crate::shared::{
    add_round_key, deflate_state_to_block, expand_block_to_state, inverse_mix_columns, inverse_shift_rows, inverse_sub_bytes, key_expansion
};

fn pad_block(block: &mut Vec<u8>) {
    let padding_needed = 16 - block.len() % 16;
    for _ in 0..padding_needed {
        block.push(padding_needed as u8);
    }
}

pub fn decrypt_one_block(data: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_key = key_expansion(*key);
    let mut output: [u8; 16] = [0; 16];
    output.copy_from_slice(data);
    let mut state = expand_block_to_state(output);

    // Perform the decryption rounds
    perform_inverse_rounds(&mut state, &round_key);
    output = deflate_state_to_block(state);

    return output;
}

fn perform_inverse_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 60]) {
    // First, apply the final round key (which doesn't involve mix_columns)
    add_round_key(
        state,
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ],
    );

    inverse_shift_rows(state);
    inverse_sub_bytes(state);

    // Proceed with the remaining rounds
    for i in (1..14).rev() {
        add_round_key(
            state,
            [
                round_keys[4 * i],
                round_keys[4 * i + 1],
                round_keys[4 * i + 2],
                round_keys[4 * i + 3],
            ],
        );
        inverse_mix_columns(state); // Applied in all but the final round
        inverse_shift_rows(state);
        inverse_sub_bytes(state);
    }

    // Apply the initial round key last
    add_round_key(
        state,
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
    );
}

#[cfg(test)]
mod test {}
