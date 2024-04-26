// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use crate::shared::{add_round_key, initialize_state_from_block, inverse_mix_columns, inverse_sub_bytes, key_expansion};

pub fn encrypt(input_path: &Path, key: &[u8; 32], output_path: &Path) -> std::io::Result<()> {
    let input_file = File::open(input_path)?;
    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;

    let mut reader = BufReader::new(input_file);
    let mut writer = BufWriter::new(output_file);

    let round_keys = key_expansion(*key);
    let mut buffer = [0u8; 16];
    let mut is_end_of_file = false;

    while !is_end_of_file {
        let mut state = [[0u8; 4]; 4];
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read < 16 {
            let mut last_block = Vec::from(&buffer[..bytes_read]);
            state = initialize_state_from_block(&last_block);
            is_end_of_file = true;
        } else {
            state = initialize_state_from_block(&buffer);
        }

        perform_rounds(&mut state, &round_keys);

        for i in 0..4 {
            for j in 0..4 {
                writer.write_all(&[state[j][i]])?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}

// this function will perform the operations of a decryption round
fn perform_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 8]) {
    add_round_key(round_keys[round_keys.len() - 1]); // add last round key

    for i in (1..14).rev() {
        // reversed so round keys are inserted in reverse
        inverse_shift_rows();
        inverse_sub_bytes(&mut state);
        add_round_key(round_keys[i]);
        inverse_mix_columns(*state);
    }

    inverse_shift_rows();
    inverse_sub_bytes(&mut state);
    add_round_key(round_keys[0]);
}

fn inverse_shift_rows(state: &mut [[u8; 4]; 4]) {
    // Second row shifts right by 1
    let temp = state[1][3];
    for i in (1..4).rev() {
        state[1][i] = state[1][i - 1];
    }
    state[1][0] = temp;

    let temp1 = state[2][3];
    let temp2 = state[2][2];
    state[2][2] = state[2][1];
    state[2][3] = state[2][0];
    state[2][0] = temp2;
    state[2][1] = temp1;

    let temp = state[3][0];
    for i in 0..3 {
        state[3][i] = state[3][i + 1];
    }
    state[3][3] = temp;
}

#[cfg(test)]
mod test {}
