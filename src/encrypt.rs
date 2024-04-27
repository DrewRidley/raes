use crate::shared::{add_round_key, deflate_state_to_block, expand_block_to_state, key_expansion, mix_columns, shift_rows, sub_bytes_state};

pub fn encrypt_one_block(data: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_keys = key_expansion(*key);
    let mut output: [u8; 16] = [0; 16];

    // Copy input data to output to use it as the state
    output.copy_from_slice(data);
    let mut state = expand_block_to_state(output);
    
    // Perform the encryption rounds
    perform_rounds(&mut state, &round_keys);
    output = deflate_state_to_block(state);

    return output;
}

fn perform_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 60]) {
    add_round_key(
        state,
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
    );

    for i in 1..14 {
        // Do 14 rounds for AES-256
        sub_bytes_state(state);
        shift_rows(state);
        mix_columns(state); // Not applied in the last round
        add_round_key(
            state,
            [
                round_keys[4 * i],
                round_keys[4 * i + 1],
                round_keys[4 * i + 2],
                round_keys[4 * i + 3],
            ],
        );
    }

    // Final round (no mix columns)
    sub_bytes_state(state);

    add_round_key(
        state,
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ],
    );
}
