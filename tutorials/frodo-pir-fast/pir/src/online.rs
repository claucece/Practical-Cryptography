use crate::offline::BaseParams;
use crate::offline::ClientParams;
use crate::utils::lwe::*;
use matrix::errors::*;
use matrix::matrix::Matrix;

/// The `Query` struct is initialized to be used for a client
/// query.
#[derive(Clone, Debug)]
pub struct Query {
    b: Vec<u32>,
    c: Vec<u32>,
}

impl Query {
    pub fn create(cp: &mut ClientParams, row_index: usize) -> ResultBoxedError<Self> {
        if Matrix::is_empty(&cp.B) || Matrix::is_empty(&cp.C) {
            return Err(Box::new(ErrorQueryParamsReused {}));
        }

        let mut b = cp.B.pop_row();
        let c = cp.C.pop_row();

        let query_indicator = get_rounding_factor(cp.plaintext_bits);

        if let Some(mut b_row) = b {
            if row_index < b_row.len() {
                let (result, check) = b_row[row_index].overflowing_add(query_indicator);
                if !check {
                    b_row[row_index] = result;
                    b = Some(b_row);
                } else {
                    return Err(Box::new(ErrorOverflownAdd {}));
                }
            } else {
                return Err(Box::new(ErrorOverflownAdd {})); // Custom error for index out of bounds
            }
        } else {
            return Err(Box::new(ErrorOverflownAdd {})); // Custom error for pop_row failure
        }

        let c_row = if let Some(c_row) = c {
            c_row
        } else {
            return Err(Box::new(ErrorOverflownAdd {})); // Custom error if c is None
        };

        Ok(Query {
            b: b.unwrap(),
            c: c_row,
        })
    }

    pub fn parse_response(&self, cp: &ClientParams, response: &Response) -> Vec<u32> {
        let rounding_factor = get_rounding_factor(cp.plaintext_bits);
        let rounding_floor = get_rounding_floor(cp.plaintext_bits);
        let plaintext_size = get_plaintext_size(cp.plaintext_bits);

        (0..cp.db_w)
            .map(|i| {
                let unscaled_res = response.c[i].wrapping_sub(self.c[i]);
                let scaled_res = unscaled_res / rounding_factor;
                let scaled_rem = unscaled_res % rounding_factor;
                let mut rounded_res = scaled_res;
                if scaled_rem > rounding_floor {
                    rounded_res += 1;
                }
                rounded_res % plaintext_size
            })
            .collect()
    }
}

/// The `Response` object wraps a response.
#[derive(Clone)]
pub struct Response {
    c: Vec<u32>,
}

impl Response {
    // Produces a response to a client query: c' = b' * DB
    pub fn create(bp: &BaseParams, q: &Query) -> Self {
        let tmp_resp = bp.trans_db.mult_by_vector(&q.b);
        let resp = tmp_resp.unwrap();

        Response { c: resp }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::format::base64_from_u32_slice;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn end_to_end() {
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

        assert!(!query.b.is_empty(), "Query's b should not be empty");
        assert!(!query.c.is_empty(), "Query's c should not be empty");

        let response = Response::create(&bp, &query);
        assert!(!response.c.is_empty(), "Response's c should not be empty");

        let val = query.parse_response(&cp, &response);
        assert!(!val.is_empty(), "Value should not be empty");

        let res = base64_from_u32_slice(&val, plaintext_bits, elem_size);
        assert_eq!(res, db_elems[0]);
        assert!(res != db_elems[1]);
    }

    #[test]
    fn end_to_end_no_reuse() {
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

        assert!(!query.b.is_empty(), "Query's b should not be empty");
        assert!(!query.c.is_empty(), "Query's c should not be empty");

        let response = Response::create(&bp, &query);
        assert!(!response.c.is_empty(), "Response's c should not be empty");

        let val = query.parse_response(&cp, &response);
        assert!(!val.is_empty(), "Value should not be empty");

        let res = base64_from_u32_slice(&val, plaintext_bits, elem_size);
        assert_eq!(res, db_elems[0]);
        assert!(res != db_elems[1]);

        let query2 = Query::create(&mut cp, 0);
        assert!(query2.is_err(), "Expected an error, but got Ok");
    }

    #[test]
    fn end_to_end_multiple() {
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
        let mut cp = ClientParams::new(
            m,
            lwe_dim,
            plaintext_bits,
            db_w,
            &bp.public_seed,
            &bp.H,
            200,
        )
        .unwrap();

        for i in 0..10 {
            let query = Query::create(&mut cp, i).unwrap();

            assert!(!query.b.is_empty(), "Query's b should not be empty");
            assert!(!query.c.is_empty(), "Query's c should not be empty");

            let response = Response::create(&bp, &query);
            assert!(!response.c.is_empty(), "Response's c should not be empty");

            let val = query.parse_response(&cp, &response);
            assert!(!val.is_empty(), "Value should not be empty");

            let res = base64_from_u32_slice(&val, plaintext_bits, elem_size);
            assert_eq!(res, db_elems[i]);
        }
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
