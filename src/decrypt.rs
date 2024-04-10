// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::fs::File;

pub fn decrypt(ciphertext: File, key: &[u8; 32], path: String) -> File {
    let round_keys = key_expansion(*key);
    perform_rounds(&round_keys);
    File::create(path).unwrap()
}


// AES-256: key length = 8 words
// block size = 4 words
// 14 rounds

// this function will perform the operations of a decryption round
fn perform_rounds(round_keys: &[u32; 60]) {

    add_round_key(round_keys[round_keys.len()-1]); // add last round key

    for i in (1..14).rev() { // reversed so round keys are inserted in reverse
        inverse_shift_rows();
        inverse_sub_bytes();
        add_round_key(round_keys[i]);
        inverse_mix_columns();
    }

    inverse_shift_rows();
    inverse_sub_bytes();
    add_round_key(round_keys[0]);
}

// generate 14 4-byte round keys for each round plus one more
// 60 bytes total

fn key_expansion(key: [u8; 32]) -> [u32; 60] {

    let mut w: [u32; 60] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let mut temp: u32 = 0;

    let mut i = 0;

    const round_constants: [u32; 10] = [0x01 << 24, 0x02 << 24, 0x04 << 24, 0x08 << 24, 0x10 << 24, 0x20 << 24, 0x40 << 24, 0x80 << 24, 0x1B << 24, 0x36 << 24];

    while i < 8 {
        w[i] = u8s_to_u32([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
        i = i + 1;
    }

    i = 8;

    while i < 60 {
        temp = w[i-1];

        if i % 8 == 0 {
            temp = sub_word(rot_word(temp)) ^ round_constants[i/8];
        } 
        else if i % 8 == 4 {
            temp = sub_word(temp);
        }

        w[i] = w[i-8] ^ temp;
        i = i + 1;
    }
    w
 }

fn u8s_to_u32(bytes: [u8; 4]) -> u32 {
    (bytes[0] as u32) << 24 | (bytes[1] as u32) << 16 | (bytes[2] as u32) << 8 | (bytes[3] as u32)
}

fn sub_word(word: u32) -> u32 {
    // do SubWord
    // I have to code S-boxes : (
    0
}

fn rot_word(mut word: u32) -> u32 {
    let first_byte = (word >> 24) & 0xFF;

    // shift the first byte out and add it to the end
    (word << 8) | first_byte
}

fn add_round_key(round_key: u32) {}

fn inverse_mix_columns() {}

fn inverse_shift_rows() {}

fn inverse_sub_bytes() {}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_sub_word() {
        // test SubWord
    }

    #[test]
    fn test_rot_word() {
        let test_word: u32 = 0x12_34_56_78;
        let rot_word_output = rot_word(test_word);
        let expected_output: u32 = 0x34_56_78_12;
        assert_eq!(rot_word_output, expected_output);
    }
}
