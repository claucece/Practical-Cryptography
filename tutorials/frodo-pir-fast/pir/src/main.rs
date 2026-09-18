use pir::offline::BaseParams;
use pir::offline::ClientParams;
use pir::online::*;

use pir::utils::format::base64_from_u32_slice;
use pir::utils::lwe::*;

use matrix::errors::*;
use matrix::matrix::Matrix;

use rand::rngs::OsRng;
use rand::RngCore;

/// The `Query` struct is initialized to be used for a client

fn main() {
    let m = 2u32.pow(12) as usize; // 2^12
    let elem_size = 2u32.pow(8) as usize; // 2^8
    let plaintext_bits = 12usize; // 12
    let lwe_dim = 512; //2^9

    // The 'array' representation of the database
    let db_elems = generate_db_elems(m, (elem_size + 7) / 8);

    let db = Matrix::new_from_vals(&db_elems, m, elem_size, plaintext_bits).unwrap();
    let db_w = db.cols.clone();
    let bp = BaseParams::new(db, m, elem_size, plaintext_bits, lwe_dim);

    // for 1 query
    let mut cp =
        ClientParams::new(m, lwe_dim, plaintext_bits, db_w, &bp.public_seed, &bp.H, 1).unwrap();

    let query = Query::create(&mut cp, 0).unwrap();
    let response = Response::create(&bp, &query);
    let val = query.parse_response(&cp, &response);
    let res = base64_from_u32_slice(&val, plaintext_bits, elem_size);
}

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
