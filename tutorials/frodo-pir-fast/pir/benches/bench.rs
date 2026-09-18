use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use matrix::matrix::Matrix;
use pir::offline::*;
use pir::online::*;
use std::time::Duration;
mod utils;
use utils::*;

const BENCH_OFFLINE: bool = true;
const BENCH_ONLINE: bool = true;

fn criterion_benchmark(c: &mut Criterion) {
    let CLIFlags {
        matrix_height,
        lwe_dim,
        elem_size,
        plaintext_bits,
        ..
    } = parse_from_env();
    let mut lwe_group = c.benchmark_group("frodo-pir");

    println!("FrodoPIR: Setting up DB for benchmarking. This might take a while...");

    let db_elems = bench_utils::generate_db_eles(matrix_height, (elem_size + 7) / 8);
    let db = Matrix::new_from_vals(&db_elems, matrix_height, elem_size, plaintext_bits).unwrap();

    println!("Setup complete, starting benchmarks");

    if BENCH_OFFLINE {
        lwe_group.sample_size(10);
        lwe_group.measurement_time(Duration::from_secs(100)); // To remove a warning, you can increase this to 500 or more.
        _bench_server_offline(
            &mut lwe_group,
            db.clone(),
            lwe_dim,
            matrix_height,
            elem_size,
            plaintext_bits,
        );

        lwe_group.sample_size(10);
        lwe_group.measurement_time(Duration::from_secs(100)); // To remove a warning, you can increase this to 500 or more.
        _bench_client_offline(
            &mut lwe_group,
            db.clone(),
            lwe_dim,
            matrix_height,
            elem_size,
            plaintext_bits,
        );
    }

    let db_w = db.cols.clone();
    if BENCH_ONLINE {
        _bench_online(
            &mut lwe_group,
            db.clone(),
            db_w,
            lwe_dim,
            matrix_height,
            elem_size,
            plaintext_bits,
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

fn _bench_server_offline(
    c: &mut BenchmarkGroup<criterion::measurement::WallTime>,
    db: Matrix,
    lwe_dim: usize,
    matrix_height: usize,
    elem_size: usize,
    plaintext_bits: usize,
) {
    println!("Starting benchmark of generation of A and H for server");

    c.bench_function(
        format!(
            "generate server db and params, DB of m x w: {:?}",
            db.print_dimensions()
        ),
        |b| {
            b.iter(|| {
                let _bp = BaseParams::new(
                    db.clone(),
                    matrix_height,
                    elem_size,
                    plaintext_bits,
                    lwe_dim,
                );
            });
        },
    );
    println!("Finished server offline steps benchmarks");
}

fn _bench_client_offline(
    c: &mut BenchmarkGroup<criterion::measurement::WallTime>,
    db: Matrix,
    lwe_dim: usize,
    matrix_height: usize,
    elem_size: usize,
    plaintext_bits: usize,
) {
    println!("Starting benchmark of generation of B and C for client. 1024 queries.");

    let bp = BaseParams::new(
        db.clone(),
        matrix_height,
        elem_size,
        plaintext_bits,
        lwe_dim,
    );
    c.bench_function(
        format!(
            "generate client offline params, DB of m x w for 1024 queries: {:?}",
            db.print_dimensions()
        ),
        |b| {
            b.iter(|| {
                let _cp = ClientParams::new(
                    matrix_height,
                    lwe_dim,
                    plaintext_bits,
                    db.cols,
                    &bp.public_seed,
                    &bp.H,
                    1024,
                );
            });
        },
    );
    println!("Finished client offline steps benchmarks");
}

fn _bench_online(
    c: &mut BenchmarkGroup<criterion::measurement::WallTime>,
    db: Matrix,
    db_w: usize,
    lwe_dim: usize,
    matrix_height: usize,
    elem_size: usize,
    plaintext_bits: usize,
) {
    println!("Starting online benches");
    let idx = 10;
    println!("Generating base params for server");
    let bp = BaseParams::new(db, matrix_height, elem_size, plaintext_bits, lwe_dim);
    println!("Generating base params for client");
    let mut cp = ClientParams::new(
        matrix_height,
        lwe_dim,
        plaintext_bits,
        db_w,
        &bp.public_seed,
        &bp.H,
        1,
    )
    .unwrap();

    println!("Starting query online benchmarks");

    c.bench_function("create client query", |b| {
        b.iter(|| {
            let p_b = &cp.B.elements.clone();
            Query::create(&mut cp, idx);
            cp.B.push_row(p_b.to_vec());
        });
    });

    let mut cp_2 = ClientParams::new(
        matrix_height,
        lwe_dim,
        plaintext_bits,
        db_w,
        &bp.public_seed,
        &bp.H,
        1,
    )
    .unwrap();
    let query = Query::create(&mut cp_2, idx).unwrap();

    c.bench_function("create server response", |b| {
        b.iter(|| {
            Response::create(&bp, &query);
        });
    });

    let mut cp_3 = ClientParams::new(
        matrix_height,
        lwe_dim,
        plaintext_bits,
        db_w,
        &bp.public_seed,
        &bp.H,
        1,
    )
    .unwrap();
    let query_3 = Query::create(&mut cp_3, idx).unwrap();
    let response = Response::create(&bp, &query_3);

    c.bench_function("client parse response", |b| {
        b.iter(|| {
            let p_c = &cp.C.elements.clone();
            query_3.parse_response(&cp, &response);
            cp.C.push_row(p_c.to_vec());
        });
    });

    println!("Finished query online benchmarks");
}

mod bench_utils {
    use rand_core::{OsRng, RngCore};
    // TODO: this is repeated so it might be worth to push to utils
    pub fn generate_db_eles(num_eles: usize, ele_byte_len: usize) -> Vec<String> {
        let mut eles = Vec::with_capacity(num_eles);
        for _ in 0..num_eles {
            let mut ele = vec![0u8; ele_byte_len];
            OsRng.fill_bytes(&mut ele);
            let ele_str = base64::encode(ele);
            eles.push(ele_str);
        }
        eles
    }
}
