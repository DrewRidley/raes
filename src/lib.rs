mod constant;
mod decrypt;
mod encrypt;

pub mod shared {
    use crate::constant::INVERSE_SBOX;
    pub use crate::constant::{ROUND_CONSTANTS, SBOX};

    pub fn key_expansion(key: [u8; 32]) -> [u32; 60] {
        const NK: usize = 8;
        const NR: usize = 14;

        let mut w: [u32; 60] = [0; 60];
        let mut temp;
        let mut i = 0;

        while i <= NK - 1 {
            w[i] = u8s_to_u32([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            i += 1;
        }

        assert!(i == NK);

        while i <= 4 * NR + 3 {
            temp = w[i - 1];
            if i % NK == 0 {
                temp = sub_word(rot_word(temp)) ^ ROUND_CONSTANTS[(i / NK) - 1]
            } else if NK > 6 && i % NK == 4 {
                temp = sub_word(temp)
            }

            w[i] = w[i - NK] ^ temp;
            i += 1;
        }

        w
    }

    fn u8s_to_u32(bytes: [u8; 4]) -> u32 {
        (bytes[0] as u32) << 24
            | (bytes[1] as u32) << 16
            | (bytes[2] as u32) << 8
            | (bytes[3] as u32)
    }

    fn sub_word(word: u32) -> u32 {
        let b3 = (word >> 24) as u8;
        let b2 = (word >> 16 & 0xFF) as u8;
        let b1 = (word >> 8 & 0xFF) as u8;
        let b0 = (word & 0xFF) as u8;

        let s3 = sub_bytes(b3, SBOX) as u32;
        let s2 = sub_bytes(b2, SBOX) as u32;
        let s1 = sub_bytes(b1, SBOX) as u32;
        let s0 = sub_bytes(b0, SBOX) as u32;

        s3 << 24 | s2 << 16 | s1 << 8 | s0
    }

    pub fn sub_bytes_state(state: &mut [[u8; 4]; 4]) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = sub_bytes(state[i][j], SBOX);
            }
        }
    }

    pub fn inverse_sub_bytes(state: &mut [[u8; 4]; 4]) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = sub_bytes(state[i][j], INVERSE_SBOX);
            }
        }
    }

    pub fn sub_bytes(input: u8, s_box: [[u8; 16]; 16]) -> u8 {
        let x = input >> 4;
        let y = input & 0xF;

        s_box[x as usize][y as usize]
    }

    fn rot_word(word: u32) -> u32 {
        let first_byte = (word >> 24) & 0xFF;

        // shift the first byte out and add it to the end
        (word << 8) | first_byte
    }

    pub fn mix_columns(state: &mut [[u8; 4]; 4]) {
        *state = apply_mix_columns(
            *state,
            &[
                [0x02, 0x03, 0x01, 0x01],
                [0x01, 0x02, 0x03, 0x01],
                [0x01, 0x01, 0x02, 0x03],
                [0x03, 0x01, 0x01, 0x02],
            ],
        );
    }

    pub fn inverse_mix_columns(state: &mut [[u8; 4]; 4]) {
        *state = apply_mix_columns(
            *state,
            &[
                [0x0E, 0x0B, 0x0D, 0x09],
                [0x09, 0x0E, 0x0B, 0x0D],
                [0x0D, 0x09, 0x0E, 0x0B],
                [0x0B, 0x0D, 0x09, 0x0E],
            ],
        )
    }

    fn apply_mix_columns(state: [[u8; 4]; 4], matrix: &[[u8; 4]; 4]) -> [[u8; 4]; 4] {
        let mut output = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];

        for j in 0..4 {
            let column = state[j];
            let mut result_column = [0; 4];

            for i in 0..4 {
                result_column[i] = gf_mul(matrix[i][0], column[0])
                    ^ gf_mul(matrix[i][1], column[1])
                    ^ gf_mul(matrix[i][2], column[2])
                    ^ gf_mul(matrix[i][3], column[3]);
            }

            output[j] = result_column;
        }

        output
    }

    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut result = 0;
        while b > 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            let high_bit_set = a & 0x80 != 0;
            a <<= 1;
            if high_bit_set {
                a ^= 0x1B; // XOR with irreducible polynomial x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        result
    }

    pub fn shift_rows(state: &mut [[u8; 4]; 4]) {
        let temp13 = state[0][3];
        let temp22 = state[0][2];
        let temp23 = state[1][3];
        let temp31 = state[0][1];
        let temp32 = state[1][2];
        let temp33 = state[2][3];

        state[0][1] = state[1][1];
        state[0][2] = state[2][2];
        state[0][3] = state[3][3];

        state[1][1] = state[2][1];
        state[1][2] = state[3][2];
        state[1][3] = temp13;

        state[2][1] = state[3][1];
        state[2][2] = temp22;
        state[2][3] = temp23;

        state[3][1] = temp31;
        state[3][2] = temp32;
        state[3][3] = temp33;
    }

    pub fn inverse_shift_rows(state: &mut [[u8; 4]; 4]) {
        let temp11 = state[0][1];
        let temp21 = state[1][1];
        let temp22 = state[0][2];
        let temp31 = state[2][1];
        let temp32 = state[1][2];
        let temp33 = state[0][3];

        state[0][1] = state[3][1];
        state[0][2] = state[2][2];
        state[0][3] = state[1][3];

        state[1][1] = temp11;
        state[1][2] = state[3][2];
        state[1][3] = state[2][3];

        state[2][1] = temp21;
        state[2][2] = temp22;
        state[2][3] = state[3][3];

        state[3][1] = temp31;
        state[3][2] = temp32;
        state[3][3] = temp33;
    }

    pub fn add_round_key(state: [[u8; 4]; 4], round_key: [u32; 4]) -> [[u8; 4]; 4] {
        let mut state_block = flatten_state_to_block(state);
        let key_block = round_key_to_block(round_key);

        for i in 0..16 {
            state_block[i] ^= key_block[i];
        }

        expand_block_to_state(state_block)
    }

    pub fn expand_block_to_state(block: [u8; 16]) -> [[u8; 4]; 4] {
        let mut output = [[0; 4]; 4];

        for i in 0..4 {
            for j in 0..4 {
                output[i][j] = block[i * 4 + j];
            }
        }

        output
    }

    pub fn flatten_state_to_block(state: [[u8; 4]; 4]) -> [u8; 16] {
        let mut output = [0; 16];

        for i in 0..4 {
            for j in 0..4 {
                output[i * 4 + j] = state[i][j];
            }
        }

        output
    }

    pub fn round_key_to_block(round_key: [u32; 4]) -> [u8; 16] {
        let mut output = [0; 16];

        for i in 0..4 {
            let key_word = round_key[i].to_le_bytes(); // Use to_le_bytes instead of to_be_bytes
            output[i * 4] = key_word[3]; // Least significant byte first
            output[i * 4 + 1] = key_word[2];
            output[i * 4 + 2] = key_word[1];
            output[i * 4 + 3] = key_word[0]; // Most significant byte last
        }

        output
    }

    #[cfg(test)]
    mod test {
        use crate::{
            decrypt::{self, decrypt_block},
            encrypt::encrypt_block,
            shared,
        };
        use shared::*;

        #[test]
        fn test_add_round_key() {
            let input = [
                [0xb2, 0x82, 0x2d, 0x81],
                [0xab, 0xe6, 0xfb, 0x27],
                [0x5f, 0xaf, 0x10, 0x3a],
                [0x07, 0x8c, 0x00, 0x33],
            ];

            let key = [0xae87dff0, 0xff11b68, 0xa68ed5fb, 0x03fc1567];

            let expected = [
                [0x1c, 0x05, 0xf2, 0x71],
                [0xa4, 0x17, 0xe0, 0x4f],
                [0xf9, 0x21, 0xc5, 0xc1],
                [0x04, 0x70, 0x15, 0x54],
            ];

            let output = add_round_key(input, key);

            assert_eq!(expected, output);

            //Do a second test case.
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
                    [0xc0, 0xd0, 0xe0, 0xf0]  // Corresponds to c0 d0 e0
                ],
                "Mismatch in round key"
            );
        }

        #[test]
        fn test_key_expansion() {
            let test_key = [
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
                0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
                0x09, 0x14, 0xdf, 0xf4,
            ];
            let expanded_keys = key_expansion(test_key);

            let expected_output = [
                0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
                0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd,
                0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a,
                0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
                0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4,
                0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
                0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab,
                0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
                0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
            ];

            assert_eq!(expanded_keys, expected_output);
        }

        #[test]
        fn test_sub_word() {
            let test_word = 0xcf4f3c09;
            let sub_word_output = sub_word(test_word);
            let expected_output = 0x8a84eb01;

            assert_eq!(sub_word_output, expected_output);
        }

        #[test]
        fn test_rot_word() {
            let test_word = 0x09cf4f3c;
            let rot_word_output = rot_word(test_word);
            let expected_output = 0xcf4f3c09;

            assert_eq!(rot_word_output, expected_output);
        }

        #[test]
        fn test_sub_bytes() {
            let test_byte = 0x0F;
            let sub_bytes_output = sub_bytes(test_byte, SBOX);
            let expected_output = 0x76;

            assert_eq!(sub_bytes_output, expected_output);
        }

        #[test]
        fn test_u8s_to_u32() {
            let test_array = [0x12, 0x34, 0x56, 0x78];
            let output = u8s_to_u32(test_array);
            let expected_output = 0x12_34_56_78;

            assert_eq!(output, expected_output);
        }

        #[test]
        fn test_mix_columns() {
            let mut state = [
                [0x63, 0x53, 0xe0, 0x8c],
                [0x09, 0x60, 0xe1, 0x04],
                [0xcd, 0x70, 0xb7, 0x51],
                [0xba, 0xca, 0xd0, 0xe7],
            ];
            let expected = [
                [0x5f, 0x72, 0x64, 0x15],
                [0x57, 0xf5, 0xbc, 0x92],
                [0xf7, 0xbe, 0x3b, 0x29],
                [0x1d, 0xb9, 0xf9, 0x1a],
            ];

            mix_columns(&mut state);
            assert_eq!(expected, state);
        }

        #[test]
        fn test_inv_mix_columns() {
            let mut state = [
                [0xbd, 0x6e, 0x7c, 0x3d],
                [0xf2, 0xb5, 0x77, 0x9e],
                [0x0b, 0x61, 0x21, 0x6e],
                [0x8b, 0x10, 0xb6, 0x89],
            ];
            let expected = [
                [0x47, 0x73, 0xb9, 0x1f],
                [0xf7, 0x2f, 0x35, 0x43],
                [0x61, 0xcb, 0x01, 0x8e],
                [0xa1, 0xe6, 0xcf, 0x2c],
            ];
            inverse_mix_columns(&mut state);
            assert_eq!(expected, state);
        }

        #[test]
        fn test_shift_rows() {
            let mut input = [
                [0x63, 0xca, 0xb7, 0x04],
                [0x09, 0x53, 0xd0, 0x51],
                [0xcd, 0x60, 0xe0, 0xe7],
                [0xba, 0x70, 0xe1, 0x8c],
            ];
            let expected = [
                [0x63, 0x53, 0xe0, 0x8c],
                [0x09, 0x60, 0xe1, 0x04],
                [0xcd, 0x70, 0xb7, 0x51],
                [0xba, 0xca, 0xd0, 0xe7],
            ];

            shift_rows(&mut input);
            assert_eq!(input, expected);
        }

        #[test]
        fn test_inverse_shift_rows() {
            let mut input = [
                [0xa7, 0xbe, 0x1a, 0x69],
                [0x97, 0xad, 0x73, 0x9b],
                [0xd8, 0xc9, 0xca, 0x45],
                [0x1f, 0x61, 0x8b, 0x61],
            ];
            let expected = [
                [0xa7, 0x61, 0xca, 0x9b],
                [0x97, 0xbe, 0x8b, 0x45],
                [0xd8, 0xad, 0x1a, 0x61],
                [0x1f, 0xc9, 0x73, 0x69],
            ];

            inverse_shift_rows(&mut input);
            assert_eq!(input, expected);
        }

        #[test]
        fn test_expand_block_to_state() {
            let input: [u8; 16] = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00,
            ];
            let expected: [[u8; 4]; 4] = [
                [0x11, 0x22, 0x33, 0x44],
                [0x55, 0x66, 0x77, 0x88],
                [0x99, 0xaa, 0xbb, 0xcc],
                [0xdd, 0xee, 0xff, 0x00],
            ];

            let output = expand_block_to_state(input);

            assert_eq!(output, expected);
        }

        #[test]
        fn test_deflate_state_to_block() {
            let input: [[u8; 4]; 4] = [
                [0x11, 0x22, 0x33, 0x44],
                [0x55, 0x66, 0x77, 0x88],
                [0x99, 0xaa, 0xbb, 0xcc],
                [0xdd, 0xee, 0xff, 0x00],
            ];

            let expected: [u8; 16] = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00,
            ];
            let deflated = flatten_state_to_block(input);

            assert_eq!(expected, deflated);
        }

        #[test]
        fn test_encrypt_decrypt() {
            // Define the inputs as strings for easier handling
            let plaintext: [u8; 16] = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ];
            // let expected: [u8; 16] = [
            //     0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            //     0x60, 0x89,
            // ];
            let key: [u8; 32] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ];

            // Encrypt and compare
            let encrypted_data = encrypt_block(&plaintext, &key);
            let decrypted_data = decrypt_block(&encrypted_data, &key);
            assert_eq!(decrypted_data, plaintext);
        }
    }
}
