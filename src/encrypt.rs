use std::{fs::{File, OpenOptions}, io::{BufReader, BufWriter, Read, Write}, path::Path};

use crate::shared::{key_expansion, mix_columns, sub_bytes};

fn pad_block(block: &mut Vec<u8>) {
    let padding_needed = 16 - block.len() % 16;
    for _ in 0..padding_needed {
        block.push(padding_needed as u8);
    }
}

pub fn encrypt(input_path: &Path, key: &[u8; 32], output_path: &Path) -> std::io::Result<()> {
    let input_file = File::open(input_path)?;
    let mut output_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;

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
            pad_block(&mut last_block);
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


///Given a block, it attempts to initialize the state from it.
///State is not directly initialized from the block, but instead its transposed like so:
fn initialize_state_from_block(block: &[u8]) -> [[u8; 4]; 4] {
    let mut state = [[0u8; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            state[j][i] = block[i * 4 + j];
        }
    }
    state
}


fn perform_rounds(state: &mut [[u8; 4]; 4], round_keys: &[u32; 8]) {
    add_round_key(state, round_keys[0]); 

    for i in 1..14 {
        // Do 14 rounds for AES-256
        shift_rows(state);
        sub_bytes(state);
        mix_columns(state); // Not applied in the last round
        add_round_key(state, round_keys[i]);
    }

    // Final round (no mix columns)
    shift_rows(state);
    sub_bytes(state);
    add_round_key(state, round_keys[round_keys.len() - 1]);
}


fn shift_rows(state: &mut [[u8; 4]; 4]) {

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