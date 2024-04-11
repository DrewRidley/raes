mod constant;
mod decrypt;
mod encrypt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub mod shared {
    pub use crate::constant::{ROUND_CONSTANTS, SBOX};

    pub fn key_expansion(key: [u8; 32]) -> [u32; 8] {
        let mut w: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

        let mut temp: u32 = 0;

        let mut i = 0;

        while i < 8 {
            w[i] = u8s_to_u32([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            i = i + 1;
        }

        i = 8;

        while i < 8 {
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

        // println!("b0: {:x}, \nb1: {:x}, \nb2: {:x}, \nb3: {:x}", b0, b1, b1, b0);
        // println!("sub_bytes of {:x}: {:x}", b0, sub_bytes(b0));

        let s3 = sub_bytes(b3) as u32;
        let s2 = sub_bytes(b2) as u32;
        let s1 = sub_bytes(b1) as u32;
        let s0 = sub_bytes(b0) as u32;

        s3 << 24 | s2 << 16 | s1 << 8 | s0
    }

    fn sub_bytes(input: u8) -> u8 {
        let x = input >> 4;
        let y = input & 0xF;

        SBOX[x as usize][y as usize]
    }

    fn rot_word(word: u32) -> u32 {
        let first_byte = (word >> 24) & 0xFF;

        // shift the first byte out and add it to the end
        (word << 8) | first_byte
    }

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
                0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
                0x0914dff4,
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
            let sub_bytes_output = sub_bytes(test_byte);
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
    }
}
