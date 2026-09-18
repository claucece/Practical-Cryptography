/// Functionality specific to the LWE setup that is used
pub mod lwe {
    const MODULUS: u64 = u32::MAX as u64 + 1;

    /// Returns a value indicating the indicator value which is used to reveal
    /// the DB row that is queried.
    pub fn get_rounding_factor(plaintext_bits: usize) -> u32 {
        (MODULUS / get_plaintext_size(plaintext_bits) as u64) as u32
    }

    /// This value indicates the bound which indicates whether a bit in the
    /// row queried to the server is set to 0 (below), or 1 (above).
    pub fn get_rounding_floor(plaintext_bits: usize) -> u32 {
        get_rounding_factor(plaintext_bits) / 2
    }

    /// Returns the modulus for the plaintext space
    pub fn get_plaintext_size(plaintext_bits: usize) -> u32 {
        2u32.pow(plaintext_bits as u32)
    }
}

pub mod sampling {
    use rand::rngs::StdRng;
    use rand_core::{OsRng, RngCore, SeedableRng};

    // Values used to denote the size of intervals that are used for
    // sampling ternary values, and a max bound that dictates when
    // randomly sampled values should be rejected.
    const TERNARY_INTERVAL_SIZE: u32 = (u32::MAX - 2) / 3;
    // Note `TERNARY_REJECTION_SAMPLING_MAX ≠ u32::MAX`
    const TERNARY_REJECTION_SAMPLING_MAX: u32 = TERNARY_INTERVAL_SIZE * 3;

    /// Simulates a ternary error by sampling randomly, using rejection
    /// sampling, from {0,1,u32::MAX} which is equivalent to {0,1,-1} when
    /// performing modular reduction.
    pub fn random_ternary() -> u32 {
        // We need to do rejection sampling for sampling randomly from 3
        // possible values: we first divide the full interval by 3, noting
        // that rounding is performed to the next _lowest_ integer.
        let mut rng = OsRng;
        loop {
            let val = rng.next_u32();
            // Reject values greater than the maximum sampling value
            if val <= TERNARY_REJECTION_SAMPLING_MAX {
                return match val {
                    v if v <= TERNARY_INTERVAL_SIZE => 0,
                    v if v <= TERNARY_INTERVAL_SIZE * 2 => 1,
                    _ => u32::MAX, // which is -1 when interpreted in i32
                };
            }
        }
    }

    /// Simulates a ternary error vector of width size by sampling randomly,
    /// using rejection sampling, from {0,1,u32::MAX}
    pub fn random_ternary_vector(width: usize) -> Vec<u32> {
        if width == 0 {
            return Vec::new(); // Return an empty vector for zero width.
        }

        (0..width).map(|_| random_ternary()).collect() // Collect results into a vector.
    }
}

/// Functionality related to manipulation of data formats that are used
pub mod format {
    use matrix::utils::format::bits_to_bytes_le;
    use matrix::utils::format::u8_to_bits_le;
    use std::convert::TryInto;

    pub fn u32_to_bits_le(x: u32, bit_len: usize) -> Vec<bool> {
        let bytes = x.to_le_bytes();
        let mut bits = Vec::with_capacity(bytes.len());
        for byte in bytes {
            bits.extend(u8_to_bits_le(byte));
        }
        bits[..bit_len].to_vec()
    }

    pub fn bytes_from_u32_slice(v: &[u32], entry_bit_len: usize, total_bit_len: usize) -> Vec<u8> {
        let remainder = total_bit_len % entry_bit_len;
        let mut bits = Vec::with_capacity(entry_bit_len * v.len());
        for i in 0..v.len() {
            // We extract either the full amount of bits, or the remainder from
            // the last index
            if i != v.len() - 1 {
                bits.extend(u32_to_bits_le(v[i], entry_bit_len));
            } else {
                bits.extend(u32_to_bits_le(v[i], remainder));
            }
        }
        bits_to_bytes_le(&bits)
    }

    pub fn base64_from_u32_slice(v: &[u32], entry_bit_len: usize, total_bit_len: usize) -> String {
        base64::encode(bytes_from_u32_slice(v, entry_bit_len, total_bit_len))
    }
}
