// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::{io::{self, Read, Write}, usize};

use crate::shared::{
    add_round_key, expand_block_to_state, flatten_state_to_block, inverse_mix_columns,
    inverse_shift_rows, inverse_sub_bytes, key_expansion,
};


pub fn decrypt_block(data: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_key = key_expansion(*key);
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
pub fn decrypt_stream<R: Read, W: Write>(mut reader: R, mut writer: W, key: &[u8; 32]) -> io::Result<()> {
    let mut buffer = [0u8; BLOCK_SIZE];
    let mut decrypted_blocks = Vec::new();

    loop {
        let read_size = reader.read(&mut buffer)?;
        if read_size == 0 { break; }

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
    *state = add_round_key(
        *state,
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ],
    );

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


#[cfg(test)]
mod tests {
    use crate::{decrypt::perform_inverse_rounds, shared::{add_round_key, expand_block_to_state, flatten_state_to_block, inverse_mix_columns, inverse_shift_rows, inverse_sub_bytes, key_expansion}};

    #[test]
    fn test_decrypt_first_round() {

        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let encrypted_data: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

    
        let round_keys = key_expansion(key);
        let mut state = expand_block_to_state(encrypted_data);
    
        state = add_round_key(
            state,
            [round_keys[4], round_keys[5], round_keys[6], round_keys[7]],
        );
        assert_eq!(
            state,
            [
                [0xd1, 0xed, 0x44, 0xfd], // Corresponds to d1 ed 44 fd
                [0x1a, 0x0f, 0x3f, 0x2a], // Corresponds to 1a 0f 3f 2a
                [0xfa, 0x4f, 0xf2, 0x7b], // Corresponds to fa 4f f2 7b
                [0x7c, 0x33, 0x2a, 0x69]  // Corresponds to 7c 33 2a 69
            ],
            "Mismatch after second round key"
        );
    
        // InvMixColumns
        inverse_mix_columns(&mut state);
        assert_eq!(
            state,
            [
                [0x62, 0x7b, 0xce, 0xb9], // Corresponds to 62 7b ce b9
                [0x99, 0x9d, 0x5a, 0xaa], // Corresponds to 99 9d 5a aa
                [0xc9, 0x45, 0xec, 0xf4], // Corresponds to c9 45 ec f4
                [0x23, 0xf5, 0x6d, 0xa5]  // Corresponds to 23 f5 6d a5
            ],
            "Mismatch after InvMixColumns"
        );
    
        // InvShiftRows
        inverse_shift_rows(&mut state);
        assert_eq!(
            state,
            [
                [0x62, 0x9d, 0xec, 0xa5], // Corresponds to 62 9d ec a5
                [0x99, 0x45, 0x6d, 0xb9], // Corresponds to 99 45 6d b9
                [0xc9, 0xf5, 0xce, 0xaa], // Corresponds to c9 f5 ce aa
                [0x23, 0x7b, 0x5a, 0xf4]  // Corresponds to 23 7b 5a f4
            ],
            "Mismatch after InvShiftRows"
        );
    
        // InvSubBytes
        inverse_sub_bytes(&mut state);
        assert_eq!(
            state,
            [
                [0xaa, 0x5e, 0xce, 0x06], // Corresponds to aa 5e ce 06
                [0xee, 0x6e, 0x3c, 0x56], // Corresponds to ee 6e 3c 56
                [0xdd, 0xe6, 0x8b, 0xac], // Corresponds to dd e6 8b ac
                [0x26, 0x21, 0xbe, 0xbf]  // Corresponds to 26 21 be bf
            ],
            "Mismatch after InvSubBytes"
        );
    
        // AddRoundKey for initial decryption (reverse of first AddRoundKey)
        state = add_round_key(
            state,
            [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
        );
        assert_eq!(
            state,
            [
                [0x00, 0x11, 0x22, 0x33], // Corresponds to 00 11 22 33
                [0x44, 0x55, 0x66, 0x77], // Corresponds to 44 55 66 77
                [0x88, 0x99, 0xaa, 0xbb], // Corresponds to 88 99 aa bb
                [0xcc, 0xdd, 0xee, 0xff]  // Corresponds to cc dd ee ff
            ],
            "Mismatch after decryption back to plaintext"
        );
    }

     #[test]
    fn test_perform_rounds() {
        let cipher: [u8; 16] = [
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

        println!("Cipher: {:x?}\nKey: {:x?}", cipher, key);

        let round_keys = key_expansion(key);
        let mut state = expand_block_to_state(cipher);
        perform_inverse_rounds(&mut state, &round_keys);
        let output = flatten_state_to_block(state);
        assert_eq!(
            output, expected,
            "Encryption failed: \nExp: {:x?}\nOut: {:x?}",
            expected, output
        );
    }
}