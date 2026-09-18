/// Functionality for matrix and vector manipulation
pub mod matrix {
    use rand::rngs::StdRng;
    use rand_core::{OsRng, RngCore, SeedableRng};

    use crate::errors::ErrorUnexpectedInputSize;
    use crate::errors::ResultBoxedError;

    /// Takes a matrix in row (column) format, and returns it in column (row) format
    pub fn transpose_matrix(matrix: &[Vec<u32>]) -> Vec<Vec<u32>> {
        let height = matrix.len();
        let width = matrix[0].len(); // assumes all entries are the same size
        let mut ret = vec![Vec::with_capacity(height); width];
        for current_row in matrix {
            for i in 0..width {
                ret[i].push(current_row[i]);
            }
        }
        ret
    }

    /// Takes a matrix and returns the [*][i] elements
    /// equivalent to `swap_matrix_fmt(xys)[i]`, but much faster
    pub fn get_matrix_second_at(matrix: &[Vec<u32>], secidx: usize) -> Vec<u32> {
        matrix.iter().map(|y| y[secidx]).collect()
    }

    /// Returns a seeded RNG for sampling values
    fn get_seeded_rng(seed: [u8; 32]) -> StdRng {
        StdRng::from_seed(seed)
    }

    /// Generates an LWE matrix from a public seed.
    /// This is in row-major order
    /// This corresponds to the generation of `A` in the paper.
    pub fn generate_lwe_matrix_from_seed(
        seed: [u8; 32],
        width: usize,
        height: usize,
    ) -> Vec<Vec<u32>> {
        let mut a = Vec::with_capacity(height);
        let mut rng = get_seeded_rng(seed);
        for _ in 0..height {
            let mut v = Vec::with_capacity(width);
            for _ in 0..width {
                v.push(rng.next_u32());
            }
            a.push(v);
        }
        a
    }

    /// Multiplies a u32 vector with a u32 column vector
    pub fn vec_mult_u32_u32(row: &[u32], col: &[u32]) -> ResultBoxedError<u32> {
        if row.len() != col.len() {
            return Err(Box::new(ErrorUnexpectedInputSize::new(format!(
                "row_len: {}, col_len:{},",
                row.len(),
                col.len(),
            ))));
        }

        let mut acc = 0u32;
        for i in 0..row.len() {
            acc = acc.wrapping_add(row[i].wrapping_mul(col[i]));
        }
        Ok(acc)
    }
}

/// Functionality related to manipulation of data formats that are used
pub mod format {
    use crate::errors::ErrorUnexpectedInputSize;
    use std::convert::TryInto;

    pub fn u8_to_bits_le(byte: u8) -> Vec<bool> {
        let mut ret = Vec::new();
        for i in 0..8 {
            ret.push(2u8.pow(i as u32) & byte > 0);
        }
        ret
    }

    pub fn bits_to_bytes_le(bits: &[bool]) -> Vec<u8> {
        let mut bytes = vec![0u8; (bits.len() + 7) / 8];
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                let idx = ((i as f64) / 8f64).floor() as usize;
                let exp = (i % 8) as u32;
                bytes[idx] += 2u8.pow(exp);
            }
        }
        bytes
    }

    pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .map(|b| u8_to_bits_le(*b))
            .collect::<Vec<Vec<bool>>>()
            .iter()
            .fold(Vec::new(), |mut acc, next| {
                acc.extend(next);
                acc
            })
    }

    pub fn u32_sized_bytes_from_vec(bytes: Vec<u8>) -> Result<[u8; 4], ErrorUnexpectedInputSize> {
        let sized_vec: [u8; 4] = match bytes.try_into() {
            Ok(b) => b,
            Err(e) => {
                return Err(ErrorUnexpectedInputSize::new(format!(
                    "Unexpected vector size: {:?}",
                    e,
                )))
            }
        };

        Ok(sized_vec)
    }

    pub fn bits_to_u32_le(bits: &[bool]) -> Result<u32, ErrorUnexpectedInputSize> {
        let mut bytes = bits_to_bytes_le(bits);
        let u32_len = std::mem::size_of::<u32>();
        let byte_len = bytes.len();
        if byte_len > u32_len {
            return Err(ErrorUnexpectedInputSize::new(format!(
                "bytes are too long to parse as u16, length: {}",
                byte_len
            )));
        }
        let padding = vec![0u8; u32_len - byte_len];
        bytes.extend(padding);

        Ok(u32::from_le_bytes(u32_sized_bytes_from_vec(bytes)?))
    }
}
