# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build and Test
- `cargo build` - Build the project
- `cargo build --release` - Build optimized release version  
- `cargo test` - Run all tests including unit, integration, and regression tests
- `cargo clippy` - Run linting checks (fix all warnings before committing)
- `cargo fmt` - Format code according to Rust standards

### Installation
- `cargo install --git https://github.com/coignard/qatsi` - Install from git
- `cargo install --path .` - Install from local source after building

## Code Architecture

### Core Components

**main.rs**: CLI entry point handling argument parsing with clap, coordinating the generation flow, and managing security presets (standard/paranoid). The main flow is: parse CLI → prompt for master secret → prompt for layers → derive key → generate output → display results.

**kdf.rs**: Hierarchical Argon2id key derivation implementing the core security model. Takes master secret and layer inputs, applies Argon2id sequentially through each layer. Uses BLAKE2b for salt expansion when salt input is too short. Contains two presets: STANDARD (64 MiB, 16 iterations) and PARANOID (128 MiB, 32 iterations).

**generator.rs**: Output generation using ChaCha20 CSPRNG with unbiased rejection sampling. Generates either mnemonic phrases (using EFF Large Wordlist) or alphanumeric passwords (90-character alphabet). All sensitive data is wrapped in `Zeroizing<T>` for automatic memory clearing.

**ui.rs**: User interaction handling secure password input, interactive layer prompting, input validation/normalization, progress indication, and formatted output display. Includes comprehensive security status indicators and entropy calculations.

**wordlist.rs**: EFF Large Wordlist management with compile-time embedding, SHA-256 integrity verification, and lazy static initialization. The wordlist contains exactly 7776 words for optimal entropy (log2(7776) ≈ 12.925 bits per word).

### Security Design

- **Memory Safety**: All sensitive data uses `Zeroizing<T>` wrapper for automatic memory clearing
- **Unicode Normalization**: All text inputs are normalized to NFC form and trimmed
- **Unbiased Sampling**: Rejection sampling ensures uniform distribution for both words and characters
- **Hierarchical KDF**: Each layer derives from the previous, creating independent key spaces
- **Integrity Protection**: Wordlist has compile-time SHA-256 verification to prevent tampering

### Key Dependencies

- `argon2`: Argon2id implementation for memory-hard key derivation
- `chacha20`: ChaCha20 stream cipher for cryptographically secure random generation
- `zeroize`: Memory zeroization for sensitive data protection
- `unicode-normalization`: Unicode NFC normalization for consistent input handling
- `blake2`: BLAKE2b for salt expansion when needed

## Testing Strategy

The test suite includes:
- **Determinism tests**: Same inputs always produce same outputs
- **Regression tests**: Known input/output pairs for both security presets
- **Unicode handling**: Multi-byte characters, normalization edge cases
- **Rejection sampling**: Validates unbiased distribution
- **Hierarchical chaining**: Different layer combinations produce independent keys
- **Security validation**: Character sets, wordlist integrity, entropy calculations

## Security Considerations

This is a cryptographic tool for generating deterministic passphrases. When working on this codebase:

- Never log or expose sensitive data (master secrets, derived keys, generated outputs)
- Maintain the `Zeroizing<T>` wrapper pattern for all sensitive data structures  
- Preserve the unbiased rejection sampling algorithms - they're critical for security
- Don't modify cryptographic constants without understanding security implications
- All new features should include comprehensive tests including security edge cases
- Follow the existing Unicode normalization patterns for any new input handling

## Commit Guidelines

Use conventional commit format: `type(scope): brief description`
- Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`
- Run `cargo fmt` and fix `cargo clippy` warnings before committing
- Add tests for new features, especially security-critical functionality