use rand::rngs::OsRng;
use rand::RngCore;

use crate::utils::sampling::*;
use matrix::errors::ResultBoxedError;
use matrix::matrix::Matrix;

pub struct BaseParams {
    dim: usize, // the lwe dimension

    m: usize,         // the number of elems in the DB
    elem_size: usize, // the size (in bits) of each element of the DB. Corresponds to `w` in paper.
    plaintext_bits: usize,

    pub public_seed: [u8; 32],
    A: Matrix,
    pub H: Matrix, // This is M in the frodopir paper
    pub db: Matrix,
    pub trans_db: Matrix,
}

impl BaseParams {
    pub fn new(db: Matrix, m: usize, elem_size: usize, plaintext_bits: usize, dim: usize) -> Self {
        let public_seed = generate_seed(); // generates the public seed, which will be used to generate A

        let A = Matrix::new_from_seed(public_seed, dim, m);

        let H = Matrix::mult_transpose_asm(&A, &db);

        let trans_db = db.transpose();

        Self {
            dim,
            m,
            elem_size,
            plaintext_bits,
            public_seed,
            A,
            H,
            db,
            trans_db,
        }
    }
}

pub struct ClientParams {
    dim: usize, // the lwe dimension
    m: usize,   // the number of elems in the DB
    pub plaintext_bits: usize,
    pub db_w: usize,

    pub B: Matrix,
    pub C: Matrix,
}

impl ClientParams {
    pub fn new(
        m: usize,
        dim: usize,
        plaintext_bits: usize,
        db_w: usize,
        public_seed: &[u8; 32],
        H: &Matrix,
        queries: usize,
    ) -> ResultBoxedError<Self> {
        if queries >= 2u64.pow(52) as usize {
            return Err(Box::from("Queries must be less than 2^52"));
        }

        let A = Matrix::new_from_seed(*public_seed, dim, m);

        let mut s_vec: Vec<u32> = vec![0; queries * dim];
        for _ in 0..queries {
            let s = random_ternary_vector(dim); // The `s` value for the client as in the paper
            s_vec.extend(s);
        }

        let mut e_vec: Vec<u32> = vec![0; queries * m];
        for _ in 0..queries {
            let e = random_ternary_vector(m); // The `s` value for the client as in the paper
            e_vec.extend(e);
        }

        let S = Matrix::with_vector(s_vec, queries, dim); // l x n
        let E = Matrix::with_vector(e_vec, queries, m); // l x m

        let mut B: Matrix = Matrix::mult_transpose(&S, &A); // l x m
        B.add(&E); // l x m

        let C = Matrix::mult_transpose_asm(&S, &H); // l x w

        Ok(Self {
            dim,
            m,
            plaintext_bits,
            db_w,
            B,
            C,
        })
    }
}

fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn generate_frodo_server_offline() {
        let m = 2u32.pow(12) as usize; // 2^12
        let elem_size = 2u32.pow(8) as usize; // 2^8
        let plaintext_bits = 12usize; // 12
        let lwe_dim = 512; //2^9

        // The 'array' representation of the database
        let db_elems = generate_db_elems(m, (elem_size + 7) / 8);

        let db = Matrix::new_from_vals(&db_elems, m, elem_size, plaintext_bits).unwrap();
        let bp = BaseParams::new(db, m, elem_size, plaintext_bits, lwe_dim);

        assert!(!Matrix::is_empty(&bp.A), "A must not be null");
        assert!(!Matrix::is_empty(&bp.H), "H must not be null");
    }

    #[test]
    fn generate_frodo_client_offline() {
        let m = 2u32.pow(12) as usize; // 2^12
        let elem_size = 2u32.pow(8) as usize; // 2^8
        let plaintext_bits = 12usize; // 12
        let lwe_dim = 512; //2^9

        // The 'array' representation of the database
        let db_elems = generate_db_elems(m, (elem_size + 7) / 8);

        let db = Matrix::new_from_vals(&db_elems, m, elem_size, plaintext_bits).unwrap();
        let db_w = db.cols.clone();
        let bp = BaseParams::new(db, m, elem_size, plaintext_bits, lwe_dim);

        // for 128 queries
        let cp = ClientParams::new(
            m,
            lwe_dim,
            plaintext_bits,
            db_w,
            &bp.public_seed,
            &bp.H,
            128,
        );

        assert!(
            !Matrix::is_empty(&cp.as_ref().unwrap().B),
            "B must not be null"
        );
        assert!(
            !Matrix::is_empty(&cp.as_ref().unwrap().C),
            "C must not be null"
        );
    }

    // This will generate random elements for test databases
    // The size of the elements is given in bytes
    fn generate_db_elems(num_elems: usize, elem_byte_len: usize) -> Vec<String> {
        let mut elems = Vec::with_capacity(num_elems);
        for _ in 0..num_elems {
            let mut elem = vec![0u8; elem_byte_len];
            OsRng.fill_bytes(&mut elem);
            let elem_str = base64::encode(elem);
            elems.push(elem_str);
        }
        elems
    }
}
