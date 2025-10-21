# Qatsi Technical Report

**Title:** Qatsi: Stateless Secret Generation via Hierarchical Memory-Hard Key Derivation

**Authors:** René Coignard, Anton Rygin

**Status:** Submitted to IACR Cryptology ePrint Archive (October 2025)

## Abstract

We present Qatsi, a hierarchical key derivation scheme using Argon2id that generates reproducible cryptographic secrets without persistent storage. The system eliminates vault-based attack surfaces by deriving all secrets deterministically from a single high-entropy master secret and contextual layers. Outputs achieve 103-312 bits of entropy through memory-hard derivation (64-128 MiB, 16-32 iterations) and provably uniform rejection sampling over 7776-word mnemonics or 90-character passwords. We formalize the hierarchical construction, prove output uniformity, and quantify GPU attack costs: $2.4 \times 10^{16}$ years for 80-bit master secrets on single-GPU adversaries under Paranoid parameters (128 MiB memory). The implementation in Rust provides automatic memory zeroization, compile-time wordlist integrity verification, and comprehensive test coverage. Reference benchmarks on Apple M1 Pro (2021) demonstrate practical usability with 544 ms Standard mode and 2273 ms Paranoid mode single-layer derivations. Qatsi targets air-gapped systems and master credential generation where stateless reproducibility outweighs rotation flexibility.

## Files

- **[qatsi-technical-report.tex](qatsi-technical-report.tex)**
- **[qatsi-technical-report.pdf](qatsi-technical-report.pdf)**

## Citation

```bibtex
@misc{coignard2025qatsi,
  author = {René Coignard and Anton Rygin},
  title = {Qatsi: Stateless Secret Generation via Hierarchical Memory-Hard Key Derivation},
  year = {2025},
  howpublished = {IACR Cryptology ePrint Archive},
  note = {Preliminary version. \url{https://github.com/coignard/qatsi}}
}
