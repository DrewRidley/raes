// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::fs::File;

pub fn decrypt<const N: usize>(ciphertext: File, key: &[u32; N], path: String) -> File {
    let round_keys = create_round_keys(*key, 11);
    perform_rounds::<N>(round_keys);
    File::create(path).unwrap()
}

// this function will perform the operations of a decryption round
fn perform_rounds<const N: usize>(round_keys: Vec<u32>) {
    add_round_key();
    inverse_mix_columns();
    shift_rows();
    inverse_sub_byte();
}

// generate 128-bit round keys for each round plus one more
// key in AES-128 is four 32-bit (4-byte) words
// eleven round keys for AES-128

// rcon_i is the round constant for round i
// rcon_i = [rc_i 0x00 0x00 0x00]
// where rc_i is byte defined as:
// rc_i = 1                             if i = 1
//        2 * rc_{i-1}                  if i > 1 AND rc_{i-1} < 0x80
//        (2 * rc_{i-1}) ^ 0x11B        if i > 1 and rc_{i-1} >= 0x80

// RotWord([b0, b1, b2, b3]) = [b1, b2, b3, b0]
// SubWord([b0, b1, b2, b3]) = [S(b0), S(b1), S(b2), S(b3)]
// W_0 .. W_{4R-1} are the 32-bit words of the expanded key

// for i = 0 .. 4R-1
// W_i =    K                                                   if i < N
//          W_{i-N} ^ SubWord(RotWord(W_{i-1})) ^ rcon_{i/N}    if i >= N AND i%N == 0
//          W_{i-N} ^ SubWord(W_{i-1})                          if (i >= N AND N > 6) AND (i%N == 4)
//          W_{i-N} ^ W_{i-1}                                   otherwise

// this could be split up into functions or made recursive I think.
fn create_round_keys<const N: usize>(key: [u32; N], number_of_rounds: u32) -> Vec<u32> {
    let mut round_keys = Vec::new();
    let mut round_constants: Vec<u32> = Vec::new();
    let mut round_number = 1;

    let mut rc_list = Vec::new();

    let rc: u8 = {
        let last_rc = rc_list[round_number - 1];
        if round_number == 1 {
            1
        } else if round_number > 1 && last_rc < 0x80 {
            2 * last_rc
        } else if round_number > 1 && last_rc >= 0x80 {
            (2 * last_rc) ^ 0x11
        } else {
            todo!()
        }
    };

    rc_list.push(rc);

    round_constants.push((rc as u32) << 24);

    let words = Vec::new();

    let w_i: u32 = {
        let last_word = words[round_number - 1];
        let inv_word = words[round_number - N];

        // Bit shifting isn't implemented for [u8], maybe there's a better way to store the words?
        if round_number < N {
            key[round_number] // figure this out
        } else if round_number >= N && (round_number % N) == 0 {
            inv_word ^ sub_word(rot_word(last_word) ^ round_constants[round_number / N])
        } else if round_number >= N && N > 6 && (round_number % N) == 4 {
            inv_word ^ sub_word(last_word)
        } else {
            inv_word ^last_word
        }
    };

    round_keys.push(w_i);
    round_number += 1;

    round_keys
}

fn sub_word(word: u32) -> u32 {
    // do SubWord
    // I have to code S-boxes : (
    0
}

fn rot_word(mut word: u32) -> u32{
    let first_byte = (word >> 24) & 0xFF ;

    (word << 8) | first_byte
}

fn add_round_key(){}

fn inverse_mix_columns(){}

fn shift_rows(){}

fn inverse_sub_byte(){}

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
