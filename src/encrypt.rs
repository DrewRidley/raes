use crate::shared::{
    add_round_key, expand_block_to_state, flatten_state_to_block, key_expansion, mix_columns,
    shift_rows, sub_bytes_state,
};

pub fn encrypt_block(data: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_keys = key_expansion(*key);
    let mut output: [u8; 16] = [0; 16];

    // Copy input data to output to use it as the state
    output.copy_from_slice(data);
    let mut state = expand_block_to_state(output);

    // Perform the encryption rounds
    perform_rounds(&mut state, &round_keys);
    output = flatten_state_to_block(state);

    return output;
}

fn perform_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 60]) {

    println!("round[ 0].input\t{:x?}", state);
    println!("round[ 0].k_sch\t{:x?}", [round_keys[0], round_keys[1], round_keys[2], round_keys[3]]);

    *state = add_round_key(
        *state,
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
    );

    for i in 1..14 {
        // Do 14 rounds for AES-256
        println!("round[ {}].start\t{:x?}", i, state);

        sub_bytes_state(state);

        println!("round[ {}].s_box\t{:x?}", i, state);
        shift_rows(state);
        println!("round[ {}].s_row\t{:x?}", i, state);

        mix_columns(state); // Not applied in the last round
        println!("round[ {}].m_col\t{:x?}", i, state);

        *state = add_round_key(
            *state,
            [
                round_keys[4 * i],
                round_keys[4 * i + 1],
                round_keys[4 * i + 2],
                round_keys[4 * i + 3],
            ],
        );
        println!("round[ {}].k_sch\t{:x?}", i, [
            round_keys[4 * i],
            round_keys[4 * i + 1],
            round_keys[4 * i + 2],
            round_keys[4 * i + 3],
        ]);

    }
    println!("round[ 14].start\t{:x?}", state);

    // Final round (no mix columns)
    sub_bytes_state(state);

    println!("round[ 14].s_box\t{:x?}", state);

    shift_rows(state);

    println!("round[ 14].s_row\t{:x?}", state);

    println!("round[ 14].k_sch\t{:x?}", state);

    *state = add_round_key(
        *state,
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ],
    );

    println!("round[ 14].start\t{:x?}", state);


}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_first_round() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let data: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];

        let round_keys = key_expansion(key);
        let mut state = expand_block_to_state(data);

        // Initial AddRoundKey
        state = add_round_key(
            state,
            [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
        );
        assert_eq!(
            state,
            [
                [0x00, 0x10, 0x20, 0x30], // Corresponds to 00 10 20 30
                [0x40, 0x50, 0x60, 0x70], // Corresponds to 40 50 60 70
                [0x80, 0x90, 0xa0, 0xb0], // Corresponds to 80 90 a0 b0
                [0xc0, 0xd0, 0xe0, 0xf0]  // Corresponds to c0 d0 e0 f0
            ],
            "Mismatch after initial add round key"
        );

        // SubBytes
        sub_bytes_state(&mut state);
        assert_eq!(
            state,
            [
                [0x63, 0xca, 0xb7, 0x04], // Corresponds to 63 ca b7 04
                [0x09, 0x53, 0xd0, 0x51], // Corresponds to 09 53 d0 51
                [0xcd, 0x60, 0xe0, 0xe7], // Corresponds to cd 60 e0 e7
                [0xba, 0x70, 0xe1, 0x8c]  // Corresponds to ba 70 e1 8c
            ],
            "Mismatch after SubBytes"
        );

        // ShiftRows
        shift_rows(&mut state);
        assert_eq!(
            state,
            [
                [0x63, 0x53, 0xe0, 0x8c], // Corresponds to 63 53 e0 8c
                [0x09, 0x60, 0xe1, 0x04], // Corresponds to 09 60 e1 04
                [0xcd, 0x70, 0xb7, 0x51], // Corresponds to cd 70 b7 51
                [0xba, 0xca, 0xd0, 0xe7]  // Corresponds to ba ca d0 e7
            ],
            "Mismatch after ShiftRows"
        );

        // MixColumns
        mix_columns(&mut state);
        assert_eq!(
            state,
            [
                [0x5f, 0x72, 0x64, 0x15], // Corresponds to 5f 72 64 15
                [0x57, 0xf5, 0xbc, 0x92], // Corresponds to 57 f5 bc 92
                [0xf7, 0xbe, 0x3b, 0x29], // Corresponds to f7 be 3b 29
                [0x1d, 0xb9, 0xf9, 0x1a]  // Corresponds to 1d b9 f9 1a
            ],
            "Mismatch after MixColumns"
        );

        // AddRoundKey for the second round key
        state = add_round_key(
            state,
            [round_keys[4], round_keys[5], round_keys[6], round_keys[7]],
        );
        assert_eq!(
            state,
            [
                [0x4f, 0x63, 0x76, 0x06], // Corresponds to 4f 63 76 06
                [0x43, 0xe0, 0xaa, 0x85], // Corresponds to 43 e0 aa 85
                [0xef, 0xa7, 0x21, 0x32], // Corresponds to ef a7 21 32
                [0x01, 0xa4, 0xe7, 0x05]  // Corresponds to 01 a4 e7 05
            ],
            "Mismatch after second round key"
        );
    }

    #[test]
    fn test_perform_rounds() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let data: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        println!("Plaintext: {:x?}\nKey: {:x?}", data, key);

        let round_keys = key_expansion(key);
        let mut state = expand_block_to_state(data);
        perform_rounds(&mut state, &round_keys);
        let output = flatten_state_to_block(state);
        assert_eq!(
            output, expected,
            "Encryption failed: \nExp: {:x?}\nOut: {:x?}",
            expected, output
        );
    }
}
