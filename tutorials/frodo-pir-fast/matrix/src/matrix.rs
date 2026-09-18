use crate::errors::ResultBoxedError;
use crate::utils::format::*;
use core::arch::aarch64::*;
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::arch::asm;
use std::fmt;

extern crate rayon;

use rayon::prelude::*;
use std::sync::Arc;
use std::sync::Mutex;

static mut TEST_STATE: bool = false;
/**
 * Basic matrix implementation. Metadata with a vector of u32; matrix
 * elements are indexed into the single vector.
 */
#[derive(Debug, Clone)]
pub struct Matrix {
    // Number of rows
    pub rows: usize,

    // Number of columns
    pub cols: usize,

    // Number of elements; rows * cols
    pub n: usize,

    // Underlying matrix data
    pub elements: Vec<u32>,
}

impl Matrix {
    /**
     * Initializes a new Matrix, wrapping the provided vector. Rows and cols must be nonzero.
     */
    pub fn with_vector(elements: Vec<u32>, rows: usize, cols: usize) -> Matrix {
        if rows == 0 || cols == 0 {
            panic!("cannot create a null matrix");
        }

        Matrix {
            rows: rows,
            cols: cols,
            n: rows * cols,
            elements: elements,
        }
    }

    /**
     * Creates a new empty matrix of the specified dimensions; underlying vector is initialized to zeroes.
     * Rows and cols must be nonzero.
     */
    pub fn new(rows: usize, cols: usize) -> Matrix {
        if rows == 0 || cols == 0 {
            panic!("cannot create a null matrix");
        }

        return Matrix::with_vector(vec![0; rows * cols], rows, cols);
    }

    /// Returns a seeded RNG for sampling values
    fn get_seeded_rng(seed: [u8; 32]) -> StdRng {
        StdRng::from_seed(seed)
    }

    /**
     * Creates a new matrix of the specified dimensions; underlying vector is initialized to random values as provided by the seed.
     * Rows and cols must be nonzero.
     */
    pub fn new_from_seed(seed: [u8; 32], rows: usize, cols: usize) -> Matrix {
        if rows == 0 || cols == 0 {
            panic!("cannot create a null matrix");
        }

        let mut ret = Vec::with_capacity(rows * cols);
        let mut rng = Self::get_seeded_rng(seed);

        for _ in 0..cols {
            for _ in 0..rows {
                ret.push(rng.next_u32());
            }
        }

        return Matrix::with_vector(ret, rows, cols);
    }

    /**
     * Creates a new matrix of the specified dimensions; underlying vector is initialized to the provided values.
     * Rows and cols must be nonzero.
     */
    pub fn new_from_vals(
        vals: &[String],
        rows: usize,
        elem_size: usize,
        plaintext_bits: usize,
    ) -> ResultBoxedError<Matrix> {
        if rows == 0 {
            panic!("cannot create a null matrix");
        }

        let mut row_width = elem_size / plaintext_bits;
        if elem_size % plaintext_bits != 0 {
            row_width += 1;
        }

        let mut result = Vec::with_capacity(rows * row_width);

        for i in 0..rows {
            let data = &vals[i];
            let bytes = base64::decode(data)?;
            let bits = bytes_to_bits_le(&bytes);

            for j in 0..row_width {
                let end_bound = (j + 1) * plaintext_bits;
                if end_bound < bits.len() {
                    result.push(bits_to_u32_le(&bits[j * plaintext_bits..end_bound])?);
                } else {
                    result.push(bits_to_u32_le(&bits[j * plaintext_bits..])?);
                }
            }
        }

        return Ok(Matrix::with_vector(result, rows, row_width));
    }

    /**
     * Returns true if the given matrix is empty; false, otherwise.
     */
    pub fn is_empty(matrix: &Matrix) -> bool {
        matrix.rows == 0 && matrix.elements.is_empty()
    }

    /**
     * Returns a deep copy of this Matrix; clones underlying vector data as well.
     */
    pub fn copy(&self) -> Matrix {
        return Matrix::with_vector(self.elements.to_vec(), self.rows, self.cols);
    }

    /**
     * Pops the last element of the matrix.
     */
    pub fn pop(&mut self) -> Option<u32> {
        let popped_element = self.elements.pop();
        if popped_element.is_some() {
            self.n -= 1;
        }
        popped_element
    }

    /**
     * Pops the last row of the matrix.
     */
    pub fn pop_row(&mut self) -> Option<Vec<u32>> {
        // Check if there are any rows to pop
        if self.rows == 0 {
            return None;
        }

        // Calculate the start and end indices of the last row
        let start_index = (self.rows - 1) * self.cols;
        let end_index = self.rows * self.cols;

        // Extract the last row elements
        let last_row = self
            .elements
            .drain(start_index..end_index)
            .collect::<Vec<u32>>();

        // Update the number of rows and elements
        self.rows -= 1;
        self.n -= self.cols;

        // Return the last row
        Some(last_row)
    }

    /**
     * Pushes a new row to the matrix.
     *
     * # Parameters
     * - `row`: The new row to be added, represented as a `Vec<u32>`.
     *
     * # Returns
     * - `Result<(), String>`: Returns `Ok(())` if the row is added successfully,
     *   or an `Err` with a message if the row does not have the correct number of columns.
     */
    pub fn push_row(&mut self, row: Vec<u32>) -> Result<(), String> {
        // Check if the row has the correct number of columns
        if row.len() != self.cols {
            return Err(format!(
                "Row length must be equal to the number of columns ({}), but got {}",
                self.cols,
                row.len()
            ));
        }

        self.elements.extend(row);
        self.rows += 1;
        self.n += self.cols;

        Ok(())
    }

    /**
     * Returns the element at (i, j).
     * Unsafe.
     */
    #[inline]
    pub fn at(&self, i: usize, j: usize) -> u32 {
        unsafe {
            return *self.elements.get_unchecked(i * self.cols + j);
        }
    }

    /**
     * Returns true if the number of rows in this Matrix equals the number of columns.
     */
    #[inline]
    pub fn is_square(&self) -> bool {
        return self.rows == self.cols;
    }

    /**
     * Adds the contents of `b` to this Matrix, and returns self. Panics if `b` is not the same size as this Matrix.
     */
    pub fn add(&mut self, b: &Matrix) -> &mut Matrix {
        if self.rows == b.rows && self.cols == b.cols {
            for i in 0..self.n {
                self.elements[i] = self.elements[i].wrapping_add(b.elements[i]);
            }
        } else {
            panic!(
                "matrices are not the same size! A: [{}, {}], B: [{}, {}]",
                self.rows, self.cols, b.rows, b.cols
            );
        }

        return self;
    }

    /**
     * Subtracts the contents of `b` from this Matrix, and returns self. Panics if `b` is not the same size as this Matrix.
     */
    pub fn sub(&mut self, b: &Matrix) -> &mut Matrix {
        if self.rows == b.rows && self.cols == b.cols {
            for i in 0..self.n {
                self.elements[i] = self.elements[i].wrapping_sub(b.elements[i]);
            }
        } else {
            panic!(
                "matrices are not the same size! A: [{}, {}], B: [{}, {}]",
                self.rows, self.cols, b.rows, b.cols
            );
        }

        return self;
    }

    /**
     * Returns true if all elements of `b` are equal to all elements of this Matrix.
     * Panics if `b` is not the same size as this Matrix.
     */
    pub fn equal(&self, b: &Matrix) -> bool {
        if self.rows == b.rows && self.cols == b.cols {
            return true;
        } else {
            panic!(
                "matrices are not the same size! A: [{}, {}], B: [{}, {}]",
                self.rows, self.cols, b.rows, b.cols
            );
        }
    }

    /// Top left index of the matrix.
    fn as_ptr(&self) -> *const u32 {
        self.elements.as_ptr()
    }
    /// Row stride in the matrix.
    fn row_stride(&self) -> usize {
        self.cols
    }
    /// Get a reference to an element in the matrix without bounds checking.
    unsafe fn get_unchecked(&self, index: [usize; 2]) -> &u32 {
        &*(self
            .as_ptr()
            .offset((index[0] * self.row_stride() + index[1]) as isize))
    }

    /**
     * Returns a new Matrix containing the transpose of this Matrix.
     */
    pub fn transpose(&self) -> Matrix {
        let mut v: Vec<u32> = Vec::with_capacity(self.n);

        unsafe {
            v.set_len(self.n);
        }
        unsafe {
            for i in 0..self.cols {
                for j in 0..self.rows {
                    *v.get_unchecked_mut(i * self.rows + j) = *self.get_unchecked([j, i]);
                }
            }
        }
        return Matrix::with_vector(v, self.cols, self.rows);
    }

    /**
     * Multiplies this Matrix by `b`, using the provided `multiplier` function.
     */
    pub fn mult(&self, b: &Matrix, multipler: fn(&Matrix, &Matrix) -> Matrix) -> Matrix {
        return multipler(self, b);
    }

    /**
     * Prints the dimensions of Matrix.
     */
    pub fn print_dimensions(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    /**
     * Multiplies the Matrix by a vector.
     */
    pub fn mult_by_vector(&self, vector: &Vec<u32>) -> Result<Vec<u32>, &'static str> {
        if vector.len() != self.cols {
            return Err("Vector length must match the number of columns in the matrix");
        }
        let mut result = vec![0u32; self.rows];
        // Parallel computation of the matrix-vector multiplication
        result.par_iter_mut().enumerate().for_each(|(i, res)| {
            let mut acc = 0u32;
            unsafe {
                // Calculate the starting index for the current row
                let row_start = i * self.cols;
                for j in 0..self.cols {
                    // Access matrix elements and vector elements without bounds checking
                    let matrix_value = *self.elements.get_unchecked(row_start + j);
                    let vector_value = *vector.get_unchecked(j);
                    acc = acc.wrapping_add(matrix_value.wrapping_mul(vector_value));
                }
            }
            *res = acc;
        });

        Ok(result)
    }

    /**
     * Naive multiplication algorithm. O(n^3).
     * Panics if matrices `a` and `b` are of incompatbile dimensions.
     */
    pub fn mult_naive(a: &Matrix, b: &Matrix) -> Matrix {
        if a.cols == b.rows {
            let m = a.rows;
            let n = b.cols;
            let p = a.cols;
            let mut c: Vec<u32> = Vec::with_capacity(m * n);

            for i in 0..m {
                for j in 0..n {
                    let mut sum: u32 = 0;
                    for k in 0..p {
                        // playing: do not use
                        sum = sum.wrapping_add(a.at(i, k).wrapping_mul(b.at(k, j)));
                        //sum.checked_add(a.at(i, k).checked_mul(b.at(k, j)).unwrap_or(0))
                        //    .unwrap_or(0);
                    }

                    c.push(sum.try_into().unwrap());
                }
            }

            return Matrix::with_vector(c, m, n);
        } else {
            panic!("Matrix sizes do not match");
        }
    }

    // Alternative
    pub fn mult_transpose_asm(a: &Matrix, b: &Matrix) -> Matrix {
        if a.cols != b.rows {
            panic!("Matrix sizes do not match");
        }

        let m = a.rows;
        let n = b.cols;
        let p = a.cols;
        let t = b.transpose();
        let mut c = vec![0u32; m * n];

        // Parallelize the outer loops with scoped threads
        c.par_chunks_mut(n).enumerate().for_each(|(i, c_row)| {
            for j in 0..n {
                let mut sum: u32 = 0;

                // Use NEON intrinsics for the inner loop
                unsafe {
                    for k in (0..p).step_by(4) {
                        // Load 4 elements from each matrix row/column into NEON registers
                        let a_vec = vld1q_u32(a.elements.as_ptr().add(i * p + k));
                        let b_vec = vld1q_u32(t.elements.as_ptr().add(j * p + k));

                        // Multiply and accumulate
                        let prod_vec = vmulq_u32(a_vec, b_vec);
                        sum = vaddvq_u32(prod_vec).wrapping_add(sum); // Horizontally sum the vector and add to sum
                    }

                    // Handle remaining elements if p is not a multiple of 4
                    for k in (p / 4 * 4)..p {
                        sum = sum.wrapping_add(a.at(i, k).wrapping_mul(t.at(j, k)));
                    }
                }

                c_row[j] = sum;
            }
        });

        Matrix::with_vector(c, m, n)
    }
    /**
     * Variant of the naive multiplication algorithm, which uses the transpose of `b`, resuting in better memory locality performance characteristics. Still O(n^3).
     * Panics if matrices `a` and `b` are of incompatbile dimensions.
     */
    pub fn mult_transpose(a: &Matrix, b: &Matrix) -> Matrix {
        if a.cols != b.rows {
            panic!("Matrix sizes do not match");
        }

        let m = a.rows;
        let n = b.cols;
        let p = a.cols;
        let t = b.transpose();
        let mut c = vec![0u32; m * n];

        c.par_chunks_mut(n).enumerate().for_each(|(i, c_row)| {
            for j in 0..n {
                let mut sum: u32 = 0;
                for k in 0..p {
                    sum = sum.wrapping_add(a.at(i, k).wrapping_mul(t.at(j, k)));
                }
                c_row[j] = sum;
            }
        });

        Matrix::with_vector(c, m, n)
    }
}

/**
 * Pretty-printing for the Matrix struct.
 */
impl fmt::Display for Matrix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let array_string = self
            .elements
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "rows: {} cols: {} n: {} array: [{}]",
            self.rows, self.cols, self.n, array_string
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_equal() {
        let v1: Vec<u32> = vec![1, 2, 3, 4];
        let v2: Vec<u32> = vec![1, 2, 3, 4];

        let a: Matrix = Matrix::with_vector(v1, 2, 2);
        let b: Matrix = Matrix::with_vector(v2, 2, 2);

        assert!(a.equal(&b));
    }

    #[test]
    fn test_add() {
        let v1: Vec<u32> = vec![1, 2, 3, 4];
        let v2: Vec<u32> = vec![9, 8, 7, 6];
        let v3: Vec<u32> = vec![10, 10, 10, 10];

        let mut a: Matrix = Matrix::with_vector(v1, 2, 2);
        let b: Matrix = Matrix::with_vector(v2, 2, 2);

        a.add(&b);

        assert!(a.elements == v3);
        assert!(a.equal(&Matrix::with_vector(v3, 2, 2)));
    }

    #[test]
    fn test_sub() {
        let v1: Vec<u32> = vec![10, 10, 10, 10];
        let v2: Vec<u32> = vec![6, 7, 8, 9];
        let v3: Vec<u32> = vec![4, 3, 2, 1];

        let mut a: Matrix = Matrix::with_vector(v1, 2, 2);
        let b: Matrix = Matrix::with_vector(v2, 2, 2);

        a.sub(&b);

        assert!(a.elements == v3);
        assert!(a.equal(&Matrix::with_vector(v3, 2, 2)));
    }

    #[test]
    fn test_at() {
        let rows = 2;
        let cols = 6;
        let v: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let a: Matrix = Matrix::with_vector(v, rows, cols);

        for i in 0..rows {
            for j in 0..cols {
                let r = a.at(i, j);
            }
        }
    }

    #[test]
    fn test_is_square() {
        let v: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let a: Matrix = Matrix::with_vector(v.to_vec(), 2, 8);
        let b: Matrix = Matrix::with_vector(v.to_vec(), 4, 4);

        assert!(!a.is_square());
        assert!(b.is_square());
    }

    #[test]
    fn test_transpose_1() {
        let rows = 2;
        let cols = 6;
        let v1: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let v2: Vec<u32> = vec![1, 7, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12];
        let a: Matrix = Matrix::with_vector(v1, rows, cols);
        let b: Matrix = Matrix::with_vector(v2, cols, rows);

        let c = a.transpose();

        assert!(c.equal(&b));
    }

    #[test]
    fn test_transpose_2() {
        let rows = 3;
        let cols = 3;
        let v1: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let v2: Vec<u32> = vec![1, 4, 7, 2, 5, 8, 3, 6, 9];
        let a: Matrix = Matrix::with_vector(v1, rows, cols);
        let b: Matrix = Matrix::with_vector(v2, cols, rows);

        let c = a.transpose();

        assert!(c.equal(&b));
    }
}
