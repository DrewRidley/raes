mod constant;
mod decrypt;
mod encrypt;

pub mod shared {
    use crate::constant::INVERSE_SBOX;
    pub use crate::constant::{ROUND_CONSTANTS, SBOX};

    pub fn key_expansion(key: [u8; 32]) -> [u32; 60] {
        let mut w: [u32; 60] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ];
        let mut temp: u32 = 0;
        let mut i = 0;

        while i < 8 {
            w[i] = u8s_to_u32([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            i = i + 1;
        }
        assert!(i == 8);

        while i < 59 {
            temp = w[i - 1];

            if i % 8 == 0 {
                temp = sub_word(rot_word(temp)) ^ ROUND_CONSTANTS[i / 8];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }

            w[i] = w[i - 8] ^ temp;
            i = i + 1;
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

    ///Given a block, it attempts to initialize the state from it.
    ///State is not directly initialized from the block, but instead its transposed like so:
    pub fn initialize_state_from_block(block: &[u8]) -> [[u8; 4]; 4] {
        let mut state = [[0u8; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                state[j][i] = block[i * 4 + j];
            }
        }
        state
    }

    pub fn shift_rows(state: &mut [[u8; 4]; 4]) {
        let temp = state[1][0];
        for i in 0..3 {
            state[1][i] = state[1][i + 1];
        }
        state[1][3] = temp;

        let temp1 = state[2][0];
        let temp2 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp1;
        state[2][3] = temp2;

        let temp = state[3][3];
        for i in (1..4).rev() {
            state[3][i] = state[3][i - 1];
        }
        state[3][0] = temp;
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

    pub fn add_round_key(state: &mut [[u8; 4]; 4], round_key: [u32; 4]) {}

    #[cfg(test)]
    mod test {

        use super::*;

        #[test]
        fn test_key_expansion() {
            let test_key = [
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
                0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
                0x09, 0x14, 0xdf, 0xf4,
            ];
            let expanded_keys = key_expansion(test_key);

            let expected_output = [
                0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
                0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
                0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
            ];

            assert_eq!(expanded_keys, expected_output);
        }

        #[test]
        fn test_sub_word() {
            let test_word = 0x12_34_56_78;
            let sub_word_output = sub_word(test_word);
            let expected_output = 0xc9_18_b1_bc;

            assert_eq!(sub_word_output, expected_output);
        }

        #[test]
        fn test_rot_word() {
            let test_word = 0x12_34_56_78;
            let rot_word_output = rot_word(test_word);
            let expected_output = 0x34_56_78_12;

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
                [0xd4, 0xe0, 0xb8, 0x1e],
                [0x27, 0xbf, 0xb4, 0x41],
                [0x11, 0x98, 0x5d, 0x52],
                [0xae, 0xf1, 0xe5, 0x30],
            ];
            let expected = [
                [0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5],
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
    }
}
