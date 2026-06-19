//! Multi-bit PBS grouping-factor benchmark (tfhe-rs 0.8.7, core_crypto, CPU/Fourier).
//!
//! Portfolio instrumentation: times ONLY `multi_bit_programmable_bootstrap_lwe_ciphertext`
//! for grouping factors g=2 and g=3, using the production GROUP_2 / GROUP_3 parameter
//! constants. Heavy setup (keygen, BSK, Fourier conversion, LUT, input encryption) is done
//! ONCE per param set, outside the timed region. Also records BSK size, key-gen time, and a
//! decrypt-and-check correctness assertion, and writes a CSV row per param set.
//!
//! The CALL SEQUENCE and ARGUMENT ORDER below are mirrored verbatim from the verified test:
//!   tfhe/src/core_crypto/algorithms/test/lwe_multi_bit_programmable_bootstrapping.rs
//!
//! ===================== STATUS (confirmed against 0.8.7) =====================
//! Items below were reconstructed from the public API (the test's own setup is #[cfg(test)]
//! and not reachable from a bench crate) and are now CONFIRMED by build/grep:
//!   1. RNG: `ActivatedRandomGenerator` + `new_seeder()` compile and run on 0.8.7.
//!   2. Param path confirmed by grep + compiler:
//!      shortint::parameters::multi_bit::p_fail_2_minus_64::ks_pbs::PARAM_MULTI_BIT_GROUP_*.
//!   3. `MultiBitPBSParameters` field accessors (pbs_base_log, pbs_level, etc.) compile.
//!   4. Encoding: native 2^64 modulus => encoding_with_padding = 1 << 63; correctness
//!      assertion passes for g=2 and g=3 across multiple plaintexts (see `assert_correct`).
//!
//! REMAINING CAVEAT (honest, not a bug): `bsk_size_bytes` is an ANALYTIC, STANDARD-DOMAIN
//! figure (u64 scalars). The PBS actually consumes the Fourier key (`fbsk`, c64 coefficients),
//! whose footprint differs; the CSV column is named `std_bsk_size_mb` to make this explicit.
//! ===========================================================================

use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;

use aligned_vec::ABox;
use concrete_fft::c64;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::*;

// Param constants live in the multi_bit submodule (verified via grep:
// shortint/parameters/multi_bit/p_fail_2_minus_64/ks_pbs.rs, re-exported by multi_bit/mod.rs).
// MultiBitPBSParameters resolves at the top level of shortint::parameters.
use tfhe::shortint::parameters::MultiBitPBSParameters;
use tfhe::shortint::parameters::multi_bit::p_fail_2_minus_64::ks_pbs::{
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
};

const CSV_PATH: &str = "multi_bit_pbs_results.csv";
/// VERIFY (thread_count): the test carries its own `thread_count`; production picks it
/// separately. Tune as you like; record it in the CSV `notes`.
const THREAD_COUNT: usize = 8;

/// core_crypto-level quantities pulled out of a production `MultiBitPBSParameters`.
struct CoreParams {
    input_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    glwe_noise_distribution: DynamicDistribution<u64>,
    lwe_noise_distribution: DynamicDistribution<u64>,
    ciphertext_modulus: CiphertextModulus<u64>,
    message_modulus: u64,
    carry_modulus: u64,
}

impl CoreParams {
    // VERIFY (item 3): every accessor on `p` below against the 0.8.7 struct definition.
    fn from_multi_bit(p: &MultiBitPBSParameters) -> Self {
        Self {
            input_lwe_dimension: p.lwe_dimension,
            glwe_dimension: p.glwe_dimension,
            polynomial_size: p.polynomial_size,
            decomp_base_log: p.pbs_base_log,
            decomp_level_count: p.pbs_level,
            grouping_factor: p.grouping_factor,
            glwe_noise_distribution: p.glwe_noise_distribution,
            lwe_noise_distribution: p.lwe_noise_distribution,
            ciphertext_modulus: p.ciphertext_modulus,
            message_modulus: p.message_modulus.0 as u64,
            carry_modulus: p.carry_modulus.0 as u64,
        }
    }
}

/// Analytic stored-BSK size in bytes.
/// Stored GGSWs = (n / g) * 2^g  (the verified allocation rule; NOT 2^g - 1).
/// Each GGSW = decomp_level_count * glwe_size rows, each row = glwe_size * polynomial_size scalars.
/// Scalar = u64 = 8 bytes. (Standard-domain count; Fourier domain differs by element type.)
fn bsk_size_bytes(p: &CoreParams) -> u64 {
    let n = p.input_lwe_dimension.0 as u64;
    let g = p.grouping_factor.0 as u64;
    let glwe_size = (p.glwe_dimension.0 as u64) + 1;
    let level = p.decomp_level_count.0 as u64;
    let poly = p.polynomial_size.0 as u64;

    let ggsw_count = (n / g) * (1u64 << g); // (n/g) * 2^g
    let scalars_per_ggsw = level * glwe_size * glwe_size * poly;
    ggsw_count * scalars_per_ggsw * (std::mem::size_of::<u64>() as u64)
}

/// Everything the timed region needs, all built once.
struct Prepared {
    input_ct: LweCiphertextOwned<u64>,
    accumulator: GlweCiphertextOwned<u64>,
    fbsk: FourierLweMultiBitBootstrapKey<ABox<[c64]>>,
    input_lwe_secret_key: LweSecretKeyOwned<u64>,
    output_lwe_secret_key: LweSecretKeyOwned<u64>,
    lwe_noise_distribution: DynamicDistribution<u64>,
    ciphertext_modulus: CiphertextModulus<u64>,
    delta: u64,
    msg_modulus: u64,
    keygen_secs: f64,
    bsk_bytes: u64,
}

fn prepare(p: &CoreParams) -> Prepared {
    // Runtime gate from the multi-bit PBS: input dimension must be divisible by the grouping
    // factor (the same `input_lwe_dimension % grouping_factor == 0` check the library enforces).
    // This also guarantees the (n/g) integer division in bsk_size_bytes is exact.
    assert_eq!(
        p.input_lwe_dimension.0 % p.grouping_factor.0,
        0,
        "input_lwe_dimension ({}) must be divisible by grouping_factor ({})",
        p.input_lwe_dimension.0,
        p.grouping_factor.0,
    );

    // ---- RNG setup ----
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    // ---- keys (mirrors test `generate_keys`, public-API form) ----
    let keygen_start = Instant::now();

    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        p.input_lwe_dimension,
        &mut secret_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        p.glwe_dimension,
        p.polynomial_size,
        &mut secret_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweMultiBitBootstrapKey::new(
        0u64,
        p.glwe_dimension.to_glwe_size(),
        p.polynomial_size,
        p.decomp_base_log,
        p.decomp_level_count,
        p.input_lwe_dimension,
        p.grouping_factor,
        p.ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        p.glwe_noise_distribution,
        &mut encryption_generator,
    );

    let mut fbsk = FourierLweMultiBitBootstrapKey::new(
        p.input_lwe_dimension,
        p.glwe_dimension.to_glwe_size(),
        p.polynomial_size,
        p.decomp_base_log,
        p.decomp_level_count,
        p.grouping_factor,
    );
    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    let keygen_secs = keygen_start.elapsed().as_secs_f64();
    let bsk_bytes = bsk_size_bytes(p);

    // ---- encoding / LUT (VERIFY item 4) ----
    // Native 2^64 modulus => encoding_with_padding = 1 << 63.
    let encoding_with_padding: u64 = 1u64 << 63;
    let msg_modulus: u64 = p.message_modulus * p.carry_modulus;
    let delta: u64 = encoding_with_padding / msg_modulus;

    let f = |x: u64| x; // identity LUT
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        p.polynomial_size,
        p.glwe_dimension.to_glwe_size(),
        msg_modulus as usize,
        p.ciphertext_modulus,
        delta,
        f,
    );

    // ---- one encrypted input ----
    let msg: u64 = msg_modulus - 1;
    let plaintext = Plaintext(msg * delta);
    let input_ct = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        plaintext,
        p.lwe_noise_distribution,
        p.ciphertext_modulus,
        &mut encryption_generator,
    );

    Prepared {
        input_ct,
        accumulator,
        fbsk,
        input_lwe_secret_key,
        output_lwe_secret_key,
        lwe_noise_distribution: p.lwe_noise_distribution,
        ciphertext_modulus: p.ciphertext_modulus,
        delta,
        msg_modulus,
        keygen_secs,
        bsk_bytes,
    }
}

/// Single PBS into a caller-owned output buffer. This is the ONLY thing we time.
#[inline]
fn run_pbs(prep: &Prepared, out: &mut LweCiphertextOwned<u64>) {
    multi_bit_programmable_bootstrap_lwe_ciphertext(
        &prep.input_ct,
        out,
        &prep.accumulator,
        &prep.fbsk,
        ThreadCount(THREAD_COUNT),
        false, // deterministic flag; false = unconstrained ordering (faster path)
    );
}

fn fresh_output(prep: &Prepared) -> LweCiphertextOwned<u64> {
    LweCiphertext::new(
        0u64,
        prep.output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        prep.ciphertext_modulus,
    )
}

/// Rounding decode: nearest multiple of delta, then divide. Mirrors the test's
/// `round_decode` (a #[cfg(test)] helper not reachable here): (x + delta/2) / delta.
/// `wrapping_add` is safe here because the noise is bounded well below delta/2 and the true
/// plaintext lies in [0, (msg_modulus-1)*delta], so x is never near u64::MAX.
fn round_decode(x: u64, delta: u64) -> u64 {
    x.wrapping_add(delta / 2) / delta
}

/// Decrypt + round-decode + assert the identity LUT held, across several plaintexts
/// (0, 1, mid, max) rather than a single value — a meaningfully stronger guarantee that the
/// bootstrap is correct over the message space, not just at one point. Runs off the hot path,
/// so re-encrypting a handful of inputs is free. Builds its own RNG to encrypt fresh inputs.
fn assert_correct(prep: &Prepared) {
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut enc_gen =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let test_messages = [0u64, 1, prep.msg_modulus / 2, prep.msg_modulus - 1];
    for &msg in &test_messages {
        let plaintext = Plaintext(msg.wrapping_mul(prep.delta));
        let input_ct = allocate_and_encrypt_new_lwe_ciphertext(
            &prep.input_lwe_secret_key,
            plaintext,
            prep.lwe_noise_distribution,
            prep.ciphertext_modulus,
            &mut enc_gen,
        );
        let mut out = fresh_output(prep);
        multi_bit_programmable_bootstrap_lwe_ciphertext(
            &input_ct,
            &mut out,
            &prep.accumulator,
            &prep.fbsk,
            ThreadCount(THREAD_COUNT),
            false,
        );
        let decrypted = decrypt_lwe_ciphertext(&prep.output_lwe_secret_key, &out);
        let decoded = round_decode(decrypted.0, prep.delta) % prep.msg_modulus;
        assert_eq!(decoded, msg, "PBS correctness check failed for msg={msg}");
    }
}

fn write_csv_header_if_new() {
    if std::path::Path::new(CSV_PATH).exists() {
        return;
    }
    // Latency stats (median/CI/std) are intentionally NOT here — criterion's report is the
    // authoritative source for those. This CSV holds the structural/keygen facts criterion
    // does not capture. std_bsk_size_mb is the analytic STANDARD-domain key size (u64 scalars),
    // not the Fourier key consumed by the PBS.
    let header = "param_set,grouping_factor_g,ggsw_per_element_2^g,input_dim_n,groups_n_div_g,\
std_bsk_size_mb,keygen_time_s,decomp_base_log,decomp_level,correct,domain,notes\n";
    let mut f = OpenOptions::new().create(true).write(true).open(CSV_PATH).unwrap();
    f.write_all(header.as_bytes()).unwrap();
}

fn append_csv_row(label: &str, p: &CoreParams, prep: &Prepared, correct: bool) {
    let g = p.grouping_factor.0;
    let n = p.input_lwe_dimension.0;
    let row = format!(
        "{label},{g},{},{n},{},{:.3},{:.3},{},{},{},Fourier,\"threads={THREAD_COUNT}; identity LUT; native 2^64; latency in criterion report\"\n",
        1usize << g,
        n / g,
        prep.bsk_bytes as f64 / (1024.0 * 1024.0),
        prep.keygen_secs,
        p.decomp_base_log.0,
        p.decomp_level_count.0,
        if correct { "Y" } else { "N" },
    );
    let mut f = OpenOptions::new().create(true).append(true).open(CSV_PATH).unwrap();
    f.write_all(row.as_bytes()).unwrap();
}

fn bench_param_set(c: &mut Criterion, label: &str, multi_bit_params: MultiBitPBSParameters) {
    let p = CoreParams::from_multi_bit(&multi_bit_params);
    let prep = prepare(&p); // heavy setup, ONCE — outside the timed region

    // correctness + CSV row (also once), then criterion times only the PBS call.
    assert_correct(&prep);
    write_csv_header_if_new();
    append_csv_row(label, &p, &prep, true);

    let mut out = fresh_output(&prep);
    c.bench_function(label, |b| {
        b.iter(|| {
            run_pbs(black_box(&prep), black_box(&mut out));
        })
    });
}

fn benches(c: &mut Criterion) {
    bench_param_set(
        c,
        "multi_bit_pbs/group_2_msg2_carry2",
        PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    );
    bench_param_set(
        c,
        "multi_bit_pbs/group_3_msg2_carry2",
        PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    );
}

criterion_group!(multi_bit_pbs, benches);
criterion_main!(multi_bit_pbs);
