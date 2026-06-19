# Multi-bit PBS Grouping-Factor Benchmark (tfhe-rs 0.8.7)

A source-verified instrumentation and analysis of the multi-bit programmable
bootstrapping (PBS) path in [tfhe-rs](https://github.com/zama-ai/tfhe-rs) 0.8.7
`core_crypto`, on CPU in the Fourier domain. It times the production grouping
factors **g=2** and **g=3** against each other and records the structural cost
each one trades for its latency.

This is framed as an architectural audit and grouping-factor tradeoff analysis,
**not** a novelty claim. The findings are consistent with Zama's published
benchmarks; the contribution here is a clean, isolated, primitive-level
measurement with the methodology made explicit.

## What this is — and is not

- It is **not** an FHE implementation. Every cryptographic operation — key
  generation, encryption, the bootstrap itself, decryption — is a tfhe-rs
  library call. The wrapper only orchestrates those calls and times the single
  PBS operation.
- Because no cryptography is reimplemented, the wrapper cannot introduce a
  silent cryptographic error. Correctness is guaranteed structurally and
  verified empirically: an encrypt → bootstrap → decrypt round trip is asserted
  across four plaintexts (0, 1, mid, max) for both parameter sets.
- There is **no key switch** in this `core_crypto` path. Sample extraction is
  present; the key-switching key lives in the higher `shortint` / `integer`
  orchestration layers, not here.

## The grouping-factor tradeoff

A higher grouping factor folds more of the blind rotation into a single external
product: g=3 processes the input in `n/3` groups instead of g=2's `n/2`, doing
fewer but larger blind-rotation steps. The cost is a larger bootstrap key — the
stored GGSW count is `(n/g) × 2^g`, so g=3 stores more key material and takes
longer to generate it. In short, g=3 trades key size and keygen time for lower
bootstrap latency.

## Results

One consistent idle run (closed applications, AC power) on CPU, Fourier domain.
Latency is taken from Criterion; the median is quoted rather than the mean
because the g=2 distribution is right-skewed and the g=3 distribution is bimodal.

| | g=2 | g=3 |
|---|---|---|
| Parameter set | `GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64` | `GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64` |
| **Median latency** | **9.6944 ms** | **7.3400 ms** |
| 95% CI | 9.6900 – 9.7006 ms | 7.2439 – 7.4855 ms |
| MAD | ~22 µs | ~344 µs |
| Distribution | tight, unimodal | bimodal |
| Input dimension `n` | 888 | 891 |
| Groups `n/g` | 444 | 297 |
| GGSWs per element `2^g` | 4 | 8 |
| Std-domain BSK size | 111.0 MB | 148.5 MB |
| Keygen time | 1.258 s | 1.435 s |
| Decomposition base log / level | 21 / 1 | 21 / 1 |

**Headline:** g=3 is faster by ~2.35 ms, roughly **24%**, at the cost of a larger
key and longer keygen.

The full Criterion reports — confidence intervals, distribution plots, and the
g=3 bimodality — are in [`report/`](report/).

### On the g=3 bimodality

g=3's latency distribution is persistently **bimodal** on this CPU (MAD ~344 µs
versus g=2's ~22 µs). An idle run stabilised the run-to-run reproducibility of
the median but did not remove the within-run bimodality, which appears
structural to how g=3's groups schedule across CPU threads rather than transient
background noise. It is reported openly rather than smoothed away.

## Two caveats stated honestly

- **`std_bsk_size_mb` is a standard-domain figure** (u64 scalars). The PBS
  actually consumes the Fourier key (c64 coefficients), whose footprint differs
  and must **not** be naively scaled from the standard-domain number. The CSV
  column is named to make this explicit.
- **`n` is not held constant** (888 vs 891). Each parameter set is independently
  security-tuned, and 888 is divisible by 2 while 891 is divisible by 3,
  satisfying the `n % g == 0` runtime gate. This therefore compares two
  production parameter sets, not an isolated grouping-factor sweep — noise and
  decomposition also differ between them.

## Verification

The call sequence and argument order in the wrapper are mirrored from the
verified test file
`tfhe/src/core_crypto/algorithms/test/lwe_multi_bit_programmable_bootstrapping.rs`.
Three derived quantities were checked against the tfhe-rs 0.8.7 source rather
than assumed:

1. **Parameter field mapping** — the wrapper pulls the PBS decomposition
   parameters (`pbs_base_log`, `pbs_level`), confirmed distinct from the
   key-switch parameters in the `MultiBitPBSParameters` struct.
2. **BSK size formula** — `(n/g) × 2^g` GGSWs, each `level × glwe_size² ×
   polynomial_size` scalars, matching the library's own size functions.
3. **Encoding** — `delta = (1 << 63) / (message_modulus × carry_modulus)` for a
   native 2^64 modulus with one padding bit, matching the LUT generator's usage.

## Files

- [`multi_bit_pbs_grouping.rs`](multi_bit_pbs_grouping.rs) — the benchmark wrapper.
- [`multi_bit_pbs_results.csv`](multi_bit_pbs_results.csv) — structural and keygen
  facts (latency lives in the Criterion reports, by design).
- [`report/`](report/) — full Criterion HTML reports for g=2 and g=3.

The implementation being measured is Zama's, not included here:
[`lwe_multi_bit_programmable_bootstrapping.rs`](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-0.8.7/tfhe/src/core_crypto/algorithms/lwe_multi_bit_programmable_bootstrapping.rs)
in tfhe-rs 0.8.7.

## Reproducing

The wrapper is a Criterion bench. It requires a `[[bench]]` stanza with
`harness = false` and `required-features = ["shortint"]`, and the `shortint`
feature enabled. Heavy setup (keygen, BSK, Fourier conversion, LUT, input
encryption) is done once per parameter set, outside the timed region; only the
single `multi_bit_programmable_bootstrap_lwe_ciphertext` call is timed.

## License

BSD-3-Clause-Clear, as a derivative of tfhe-rs. See [`LICENSE`](LICENSE).
