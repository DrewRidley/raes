// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::{
    io::{self, Read, Write},
    usize,
};

use crate::shared::{
    add_round_key, expand_block_to_state, flatten_state_to_block, inverse_key_expansion,
    inverse_mix_columns, inverse_shift_rows, inverse_sub_bytes,
};

pub fn decrypt_block(data: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_key = inverse_key_expansion(*key);
    let mut output: [u8; 16] = [0; 16];
    output.copy_from_slice(data);
    let mut state = expand_block_to_state(output);

    // Perform the decryption rounds
    //perform_inverse_rounds(&mut state, &round_key);
    perform_inverse_rounds(&mut state, &round_key);
    output = flatten_state_to_block(state);

    return output;
}

const BLOCK_SIZE: usize = 16;
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8; 32],
) -> io::Result<()> {
    let mut buffer = [0u8; BLOCK_SIZE];
    let mut decrypted_blocks = Vec::new();

    loop {
        let read_size = reader.read(&mut buffer)?;
        if read_size == 0 {
            break;
        }

        let decrypted = decrypt_block(&buffer, key);
        decrypted_blocks.push((decrypted.to_vec(), read_size));
    }

    // Write all blocks except the last one fully
    for (block, size) in decrypted_blocks.iter().take(decrypted_blocks.len() - 1) {
        writer.write_all(block)?;
    }

    // Write the last block according to its original size
    if let Some((last_block, size)) = decrypted_blocks.last() {
        writer.write_all(&last_block[..*size])?;
    }

    Ok(())
}

fn perform_inverse_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 60]) {
    println!("round[ 0].iinput\t{:x?}", state);
    println!(
        "round[ 0].ik_sch\t{:x?}",
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ]
    );
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

    // Do the rest of the rounds in reverse order
    for i in (1..14).rev() {
        println!("round[ {}].istart\t{:x?}", 14 - i, state);

        inverse_sub_bytes(state);
        println!("round[ {}].is_box\t{:x?}", 14 - i, state);

        inverse_shift_rows(state);
        println!("round[ {}].is_row\t{:x?}", 14 - i, state);

        inverse_mix_columns(state);
        println!("round[ {}].im_col\t{:x?}", 14 - i, state);

        println!(
            "round[ {}].ik_sch\t{:x?}",
            14 - i,
            [
                round_keys[4 * i],
                round_keys[4 * i + 1],
                round_keys[4 * i + 2],
                round_keys[4 * i + 3],
            ]
        );

        *state = add_round_key(
            *state,
            [
                round_keys[4 * i],
                round_keys[4 * i + 1],
                round_keys[4 * i + 2],
                round_keys[4 * i + 3],
            ],
        );
    }
    println!("round[ 14].istart\t{:x?}", state);

    inverse_sub_bytes(state);
    println!("round[ 14].is_box\t{:x?}", state);

    inverse_shift_rows(state);
    println!("round[ 14].is_row\t{:x?}", state);

    println!(
        "round[ 14].ik_sch\t{:x?}",
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]]
    );

    // Last AddRoundKey with the first round key
    *state = add_round_key(
        *state,
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
    );
    println!("round[ 14].ioutput\t{:x?}", state);
}

#[cfg(test)]
mod tests {
    use crate::{
        decrypt::perform_inverse_rounds,
        shared::{
            add_round_key, expand_block_to_state, flatten_state_to_block, inverse_key_expansion,
            inverse_mix_columns, inverse_shift_rows, inverse_sub_bytes,
        },
    };

    #[test]
    fn test_decrypt_first_round() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let encrypted_data: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        let round_keys = inverse_key_expansion(key);
        let mut state = expand_block_to_state(encrypted_data);

        state = add_round_key(
            state,
            [
                round_keys[4 * 14],
                round_keys[4 * 14 + 1],
                round_keys[4 * 14 + 2],
                round_keys[4 * 14 + 3],
            ],
        );
        assert_eq!(
            state,
            [
                [0xaa, 0x5e, 0xce, 0x06],
                [0xee, 0x6e, 0x3c, 0x56],
                [0xdd, 0xe6, 0x8b, 0xac],
                [0x26, 0x21, 0xbe, 0xbf]
            ],
            "Mismatch after first round key"
        );

        // InvSubBytes
        inverse_sub_bytes(&mut state);
        assert_eq!(
            state,
            [
                [0x62, 0x9d, 0xec, 0xa5],
                [0x99, 0x45, 0x6d, 0xb9],
                [0xc9, 0xf5, 0xce, 0xaa],
                [0x23, 0x7b, 0x5a, 0xf4]
            ],
            "Mismatch after InvSubBytes"
        );

        // InvShiftRows
        inverse_shift_rows(&mut state);
        assert_eq!(
            state,
            [
                [0x62, 0x7b, 0xce, 0xb9],
                [0x99, 0x9d, 0x5a, 0xaa],
                [0xc9, 0x45, 0xec, 0xf4],
                [0x23, 0xf5, 0x6d, 0xa5]
            ],
            "Mismatch after InvShiftRows"
        );

        // InvMixColumns
        inverse_mix_columns(&mut state);
        assert_eq!(
            state,
            [
                [0xe5, 0x1c, 0x95, 0x02],
                [0xa5, 0xc1, 0x95, 0x05],
                [0x06, 0xa6, 0x10, 0x24],
                [0x59, 0x6b, 0x2b, 0x07]
            ],
            "Mismatch after InvMixColumns"
        );

        state = add_round_key(
            state,
            [
                round_keys[4 * 13],
                round_keys[4 * 13 + 1],
                round_keys[4 * 13 + 2],
                round_keys[4 * 13 + 3],
            ],
        );
        assert_eq!(
            state,
            [
                [0xd1, 0xed, 0x44, 0xfd],
                [0x1a, 0x0f, 0x3f, 0x2a],
                [0xfa, 0x4f, 0xf2, 0x7b],
                [0x7c, 0x33, 0x2a, 0x69]
            ],
            "Mismatch after second round key"
        );
    }

    #[test]
    fn test_perform_inverse_rounds() {
        let ciphertext: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let expected: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];

        println!("Cipher: {:x?}\nKey: {:x?}", ciphertext, key);

        let round_keys = inverse_key_expansion(key);
        let mut state = expand_block_to_state(ciphertext);
        perform_inverse_rounds(&mut state, &round_keys);
        let output = flatten_state_to_block(state);
        assert_eq!(
            output, expected,
            "Encryption failed: \nExp: {:x?}\nOut: {:x?}",
            expected, output
        );
    }
}
