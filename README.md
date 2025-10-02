<img src="https://github.com/coignard/qatsi/blob/main/assets/logo.svg?raw=true" alt="Qatsi Logo" height="72">

[![CI](https://github.com/coignard/qatsi/actions/workflows/ci.yml/badge.svg)](https://github.com/coignard/qatsi/actions/workflows/ci.yml)

Hierarchical deterministic passphrase generator using hierarchical Argon2id key derivation. Generates cryptographically secure mnemonic or alphanumeric passphrases without storing anything to disk.

Designed for master passwords and other high-entropy secrets that need to be reproduced on-demand from a master secret and context layers.

## Install

```bash
cargo install --git https://github.com/coignard/qatsi
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
# 8-word mnemonic (≈103 bits entropy)
qatsi --mode mnemonic --security standard

# 24-word mnemonic (≈310 bits entropy)
qatsi --mode mnemonic --security paranoid

# 20-character password (≈130 bits entropy)
qatsi --mode password --security standard

# 48-character password (≈312 bits entropy)
qatsi --mode password --security paranoid
```

Example usage:

```
$ qatsi

In [0]: *************
In [1]: github.com
In [2]: 2025
In [3]:

Out[0]:
excusable-suffice-crepe-shower-amends-spoils-pebbly-specks

Settings:
  ├─ KDF        [✓] Argon2id (m=64 MiB, t=16, p=6)
  ├─ Master     [✓] 23 character(s)
  ├─ Layers     [✓] 2 layers
  │  ├─ [✓] In [1]: 10 character(s)
  │  └─ [✓] In [2]: 4 character(s)
  ├─ PRNG       ChaCha20 (256-bit)
  ├─ Sampling   Unbiased rejection
  └─ Output     8 words

Stats:
  ├─ Entropy    [✓] 103.4 bits (Strong)
  ├─ Length     [✓] 58 character(s)
  ├─ Words      [✓] 8
  ├─ Wordlist   EFF Large (7776 words)
  └─ Time       1.0s

[✓] Security: Strong
```

## How it works

Given master secret $M$ and context layers $L_1, \ldots, L_n$, hierarchical key derivation:

$$K_0 = M$$

$$K_i = \text{Argon2id}(K_{i-1}, \text{salt}(L_i), m, t, p, \ell) \quad \forall i \in [1, n]$$

**Configurations:**

| Profile | Memory | Iterations | Parallelism | Time (M1) |
|---------|--------|------------|-------------|-----------|
| Standard | 64 MiB | 16 | 6 threads | ~0.5s/layer |
| Paranoid | 128 MiB | 32 | 6 threads | ~1.0s/layer |

**Output entropy:**

- Mnemonic: $w \times \log_2(7776) \approx w \times 12.925$ bits, where $w \in \{8, 24\}$
- Password: $\ell \times \log_2(90) \approx \ell \times 6.492$ bits, where $\ell \in \{20, 48\}$

Final key $K_n$ seeds ChaCha20 for unbiased rejection sampling:

- Mnemonic: Reject if $r \geq 62208$ (ensures uniform selection from 7776 words)
- Password: Reject if $b \geq 180$ (ensures uniform selection from 90-character alphabet)

## Security

**Argon2id parameters** resist GPU/ASIC attacks through memory-hardness:

- Standard: 64 MiB memory, 16 iterations, 6-thread parallelism
- Paranoid: 128 MiB memory, 32 iterations, 6-thread parallelism

**Attack resistance:** For 80-bit master secret with paranoid mode, expected brute-force time exceeds $3.8 \times 10^8$ years at 50,000 H/s (500 GPUs @ 100 H/s each).

**Cryptographic properties:**

- EFF Large Wordlist (7776 words) embedded with compile-time SHA-256 verification
- ChaCha20 CSPRNG (256-bit security)
- Unbiased rejection sampling (provably uniform distribution)
- Automatic memory zeroization via `Zeroizing<T>`

**Threat model:** Protects against offline brute-force, dictionary attacks, GPU acceleration, supply-chain attacks (wordlist tampering), and memory disclosure. Does not provide forward secrecy (master compromise exposes all derivations).

## Test

```bash
cargo test
```

Test suite includes:
- Determinism verification (identical inputs → identical outputs)
- Wordlist integrity (7776 words, SHA-256, known indices)
- Rejection sampling correctness
- Different layer combinations produce independent keys
- Character set validation (exactly 90 chars)

## License

GPL-3.0
