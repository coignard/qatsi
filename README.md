<img src="https://github.com/coignard/qatsi/blob/main/assets/logo.svg?raw=true" alt="Qatsi Logo" height="72">

[![CI](https://github.com/coignard/qatsi/workflows/CI/badge.svg)](https://github.com/coignard/qatsi/actions)
[![CodeQL](https://github.com/coignard/qatsi/workflows/CodeQL/badge.svg)](https://github.com/coignard/qatsi/security/code-scanning)
[![Crates.io](https://img.shields.io/crates/v/qatsi.svg)](https://crates.io/crates/qatsi)
[![Documentation](https://docs.rs/qatsi/badge.svg)](https://docs.rs/qatsi)
[![License: GPL-3.0-or-later](https://img.shields.io/crates/l/qatsi.svg)](LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/coignard)

Stateless secret generation via hierarchical memory-hard key derivation using Argon2id. Generates cryptographically secure mnemonic or alphanumeric secrets without storing anything to disk.

> [!CAUTION]
> Qatsi is not a password manager. It is a hierarchical deterministic key derivation tool designed for generating reproducible secrets from high-entropy master secrets for high-stakes credentials: password manager master passwords, full-disk encryption passphrases, PGP and SSH key passphrases, and access to critical services on air-gapped systems where credential loss is unacceptable.
>
> For day-to-day website passwords with varying policies, rotation requirements, and existing credentials, use a traditional password manager like KeePassXC or Bitwarden. Use Qatsi where you need reproducible secrets across systems without persistent storage. See [SECURITY.md](SECURITY.md) for threat model and design limitations, or the [technical report](https://doi.org/10.48550/arXiv.2510.18614) for detailed cryptographic analysis.

## Install

```bash
cargo install qatsi
```

Or build from source:

```bash
git clone https://github.com/coignard/qatsi
cd qatsi
cargo build --release
sudo cp target/release/qatsi /usr/local/bin/
```

## Usage

```bash
# 8-word mnemonic (103.4 bits entropy)
qatsi --mode mnemonic --security standard

# 24-word mnemonic (310.2 bits entropy)
qatsi --mode mnemonic --security paranoid

# 20-character password (129.8 bits entropy)
qatsi --mode password --security standard

# 48-character password (311.6 bits entropy)
qatsi --mode password --security paranoid
```

You can override the default security presets with custom parameters for fine-grained control:

```bash
# Generate a 12-word mnemonic with custom KDF memory (256 MiB)
qatsi --mode mnemonic --words 12 --kdf-memory 256

# Generate a 32-character password with custom KDF iterations
qatsi --mode password --length 32 --kdf-iterations 24
```

Example usage:

```
$ qatsi --mode password --security paranoid
In [0]: ****************
In [1]: 0802BDCD52656EE9 # PGP Key ID
In [2]: Somewhere        # Place created
In [3]:

Out[0]:
3:L;M3ks1ByuQ0d6b-Z*|MDtRKjQ6t:L>YjhXg+@@%emz{|m

Settings:
  ├─ KDF        [✓] Argon2id (m=128 MiB, t=32, p=6)
  ├─ Master     [✓] 16 bytes (16 chars)
  ├─ Layers     [✓] 2 layers
  │  ├─ [✓] In [1]: 16 bytes (16 chars)
  │  └─ [✓] In [2]: 9 bytes (9 chars)
  ├─ Keystream  ChaCha20 (256-bit)
  ├─ Sampling   Unbiased rejection
  └─ Output     48 chars

Stats:
  ├─ Entropy    [✓] 311.6 bits (Paranoid)
  ├─ Length     [✓] 48 chars
  ├─ Charset    90 chars
  └─ Time       4.6s

[✓] Security: Paranoid
```

## How it works

Qatsi combines a master secret with context layers through iterative Argon2id hashing. The final derived key seeds a ChaCha20 stream cipher for unbiased generation of mnemonics or passwords. For a detailed cryptographic analysis, see the [technical report](https://doi.org/10.48550/arXiv.2510.18614).

Let $K_0 = M$ (master secret). For each layer $L_i$ with $i \in [1, n]$:

$$K_i = \text{Argon2id}(K_{i-1}, \text{Salt}(L_i), m, t, p, \ell)$$

where:

$$\text{Salt}(L) = \begin{cases}
L & \text{if } |L| \geq 16 \text{ bytes} \\
\text{BLAKE2b-512}(L) & \text{if } |L| < 16 \text{ bytes}
\end{cases}$$

Parameters:

- $K_{i-1}$ — previous derived key (or master secret for $i=1$)
- $m$ — memory cost (KiB): 65536 (Standard) or 131072 (Paranoid)
- $t$ — iterations: 16 (Standard) or 32 (Paranoid)
- $p$ — parallelism: 6
- $\ell$ — output length: 32 bytes (256 bits)

```
K_0 ────┐
        ├─── Argon2id(K_0, Salt(L_1), m, t, p) ──→ K_1
L_1 ────┘

K_1 ────┐
        ├─── Argon2id(K_1, Salt(L_2), m, t, p) ──→ K_2
L_2 ────┘

    ⋮

K_n-1 ──┐
        ├─── Argon2id(K_n-1, Salt(L_n), m, t, p) ──→ K_n
L_n ────┘

K_n ──→ ChaCha20(K_n) ──→ Rejection sampling ──→ Output
```

### Unbiased rejection sampling

Rejection sampling eliminates modulo bias by rejecting values outside a uniform range.

Mnemonics (EFF Large Wordlist, 7776 words):

```
Threshold T = ⌊2^16 / 7776⌋ × 7776 = 8 × 7776 = 62208

Algorithm:
  1. Sample 16-bit value r from ChaCha20 keystream
  2. If r < 62208:
       Select word: W[r mod 7776]
  3. Else: reject and repeat

Expected samples per word: 65536 / 62208 ≈ 1.053
Rejection rate: 3328 / 65536 ≈ 5.08%
```

Passwords (90-character alphabet: A-Z, a-z, 0-9, 28 symbols):

```
Threshold T = 256 - (256 mod 90) = 180

Algorithm:
  1. Sample 8-bit value b from ChaCha20 keystream
  2. If b < 180:
       Select character: A[b mod 90]
  3. Else: reject and repeat

Expected samples per character: 256 / 180 ≈ 1.422
Rejection rate: 76 / 256 ≈ 29.69%
```

This provably achieves uniform distribution (proven in Section 3.4 of the technical report).

### Output entropy

Mnemonics (7776-word EFF Large Wordlist):

$$H_{\text{mnemonic}} = w \times \log_2(7776) = w \times 12.925 \text{ bits}$$

- Standard (8 words): 103.4 bits
- Paranoid (24 words): 310.2 bits

Passwords (90-character alphabet):

$$H_{\text{password}} = \ell \times \log_2(90) = \ell \times 6.492 \text{ bits}$$

- Standard (20 characters): 129.8 bits
- Paranoid (48 characters): 311.6 bits

## Performance

Measured on Apple M1 Pro (2021), 16 GB RAM, Rust 1.90 release build, median of 5 runs:

| Operation | Time (ms) | Memory (MB) |
|-----------|-----------|-------------|
| Standard (64 MiB, t=16, p=6) | | |
| Single layer | 544 | 64 |
| 3 layers | 1613 | 64 |
| Paranoid (128 MiB, t=32, p=6) | | |
| Single layer | 2273 | 128 |
| 3 layers | 6697 | 128 |
| Output generation | <1 | <1 |

Output generation (1000 iterations): mnemonic 2 µs, password 3 µs.

Time complexity: $O(n)$ in layer count. Space complexity: $O(1)$ in output size, $O(m)$ in KDF memory.

## Test

Run the complete test suite:

```bash
cargo test
```

## Documentation

- [Technical report](https://doi.org/10.48550/arXiv.2510.18614)
- [SECURITY.md](SECURITY.md)

## License

GPL-3.0-or-later
