// This file holds the code to decrypt using our implementation of the AES algorithm.

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use crate::shared::{
    add_round_key, initialize_state_from_block, inverse_mix_columns, inverse_shift_rows,
    inverse_sub_bytes, key_expansion,
};

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
fn perform_rounds(mut state: &mut [[u8; 4]; 4], round_keys: &[u32; 60]) {
    add_round_key(
        state,
        [
            round_keys[4 * 14],
            round_keys[4 * 14 + 1],
            round_keys[4 * 14 + 2],
            round_keys[4 * 14 + 3],
        ],
    ); // add last round key

    for i in (1..14).rev() {
        // reversed so round keys are inserted in reverse
        inverse_sub_bytes(state);
        inverse_shift_rows(state);
        inverse_mix_columns(state);
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

    inverse_sub_bytes(state);
    inverse_shift_rows(state);
    add_round_key(
        state,
        [round_keys[0], round_keys[1], round_keys[2], round_keys[3]],
    );
}

#[cfg(test)]
mod test {}
